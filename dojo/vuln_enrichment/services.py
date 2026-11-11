"""Public-source enrichment for CVSS vectors and exploit signals (CLAUDE.md §7).

Fills three columns that dojo.ssvc.services' derive_exploitation/derive_automatable/
derive_technical_impact already read but that no existing DefectDojo code populates from a
live network source (confirmed by reading dojo/ first, per CLAUDE.md §13 — see the fork's
research notes): Vulnerability.known_exploited/kev_date/kev_due_date/ransomware_used (CISA
KEV), Vulnerability.epss_score/epss_percentile (FIRST.org EPSS), Vulnerability.cvssv3_vector
(NVD API 2.0).

Vulnerability (dojo/vulnerability/models.py) is the fork's existing global per-CVE cache —
its docstring already describes this exact job ("Populating these columns is the enrichment
owner's job"); its enrichment_updated timestamp is the source/fetched_at provenance CLAUDE.md
§7 asks for, so no new cache or provenance model is added here. Only `cvssv3_vector` is a new
column: the entity had no CVSS field at all (see DEFECTDOJO_MODIFICATIONS.md).

Two steps, kept separate (both are idempotent and safe to re-run):
1. enrich_vulnerabilities() — fetch public data, update the Vulnerability cache.
2. project_enrichment_to_findings() — copy cache values onto the matching Finding rows'
   own epss_score/epss_percentile/known_exploited/kev_date/cvssv3 columns (gap-fill only,
   by default), via bulk_update (not .save()) so this silent background pass does not
   trigger Finding.save()'s notification/JIRA-sync side effects.

CLAUDE.md §7: "Awaria źródła nie blokuje importu ani decyzji" — each source is fetched and
applied independently; one source failing (network error, bad response) never prevents the
other two from updating. No step here ever runs synchronously from an import or UI request;
it's invoked from dojo.management.commands.vuln_enrich only (CLAUDE.md §6.5 recalculation
triggers and Celery-beat wiring for this are not implemented here, same as ssvc_recompute).
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Iterable
from typing import Any

import requests

logger = logging.getLogger(__name__)

HTTP_TIMEOUT_SECONDS = 15
# Identifies the client to the public API operator without naming this instance/user —
# CLAUDE.md's "treat user/project details as private" applies to outbound headers too.
USER_AGENT = "vulnmgmt-ssvc-enrichment/1.0"

KEV_URL = os.environ.get(
    "DD_VULN_ENRICH_KEV_URL",
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
)
EPSS_URL = os.environ.get("DD_VULN_ENRICH_EPSS_URL", "https://api.first.org/data/v1/epss")
NVD_URL = os.environ.get("DD_VULN_ENRICH_NVD_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")

EPSS_BATCH_SIZE = int(os.environ.get("DD_VULN_ENRICH_EPSS_BATCH_SIZE", "100"))


def nvd_api_key() -> str | None:
    """Optional NVD API key (CLAUDE.md §7: "NVD API 2.0 (z kluczem API i rate limitingiem)")."""
    return os.environ.get("DD_VULN_ENRICH_NVD_API_KEY") or None


def nvd_min_interval_seconds() -> float:
    """
    Seconds to wait between NVD requests.

    NVD's published public rate limit is 5 requests / rolling 30s without a key, 50/30s with
    one — these defaults (6.0s / 0.65s) stay a safety margin under each. Override via
    DD_VULN_ENRICH_NVD_MIN_INTERVAL_SECONDS for a private/mirrored NVD endpoint.
    """
    raw = os.environ.get("DD_VULN_ENRICH_NVD_MIN_INTERVAL_SECONDS")
    if raw is not None:
        try:
            return float(raw)
        except ValueError:
            logger.warning("Invalid DD_VULN_ENRICH_NVD_MIN_INTERVAL_SECONDS=%r, using default", raw)
    return 0.65 if nvd_api_key() else 6.0


class EnrichmentSourceError(Exception):
    """One source (KEV/EPSS/NVD) failed. Caught per-source by the orchestrator, never fatal."""


def _get_json(url: str, *, params: dict[str, Any] | None = None, headers: dict[str, str] | None = None) -> Any:
    merged_headers = {"User-Agent": USER_AGENT, **(headers or {})}
    try:
        response = requests.get(url, params=params, headers=merged_headers, timeout=HTTP_TIMEOUT_SECONDS)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as exc:
        raise EnrichmentSourceError(f"GET {url} failed: {exc}") from exc
    except ValueError as exc:  # json decode error
        raise EnrichmentSourceError(f"GET {url} returned invalid JSON: {exc}") from exc


def fetch_kev_catalog() -> dict[str, dict[str, Any]]:
    """
    Whole CISA KEV catalog, keyed by CVE id.

    One bulk fetch regardless of how many CVEs we hold (CLAUDE.md §7 "mirror przyrostowy, nie
    pełne pobieranie przy każdym cyklu" means caching/not re-deriving our own data each run,
    not avoiding this call — the catalog has no per-CVE lookup endpoint and is a few MB).
    Raises EnrichmentSourceError on any network/parse failure.
    """
    payload = _get_json(KEV_URL)
    catalog: dict[str, dict[str, Any]] = {}
    for entry in payload.get("vulnerabilities", []):
        cve_id = entry.get("cveID")
        if not cve_id:
            continue
        catalog[cve_id] = {
            "kev_date": entry.get("dateAdded") or None,
            "kev_due_date": entry.get("dueDate") or None,
            "ransomware_used": entry.get("knownRansomwareCampaignUse", "Unknown") == "Known",
        }
    return catalog


def fetch_epss_scores(cve_ids: list[str]) -> dict[str, dict[str, float]]:
    """
    EPSS score/percentile for the given CVE ids, batched (EPSS_BATCH_SIZE per request).

    Raises EnrichmentSourceError on the first failing batch — callers that want partial
    results on a mid-run failure should catch per-batch themselves; vuln_enrich's orchestrator
    treats EPSS as one source and skips it entirely on failure, same as KEV/NVD.
    """
    scores: dict[str, dict[str, float]] = {}
    unique_ids = list(dict.fromkeys(cve_ids))
    for start in range(0, len(unique_ids), EPSS_BATCH_SIZE):
        batch = unique_ids[start:start + EPSS_BATCH_SIZE]
        payload = _get_json(EPSS_URL, params={"cve": ",".join(batch)})
        for row in payload.get("data", []):
            cve_id = row.get("cve")
            if not cve_id:
                continue
            try:
                scores[cve_id] = {
                    "epss_score": float(row["epss"]),
                    "epss_percentile": float(row["percentile"]),
                }
            except (KeyError, TypeError, ValueError):
                logger.warning("Unparseable EPSS row for %s: %r", cve_id, row)
    return scores


def fetch_nvd_cvss_vector(cve_id: str) -> str | None:
    """
    This CVE's CVSSv3 vector from NVD API 2.0 (v3.1 preferred over v3.0; "Primary" source
    preferred over others), or None if NVD has no CVSSv3 metric for it (e.g. CVSSv4-only, or
    not yet scored) — that is a legitimate empty result, not an error.

    Raises EnrichmentSourceError on network/parse failure (distinct from "no vector"), so the
    caller can tell "checked, nothing there" (leave cvssv3_vector NULL, no retry needed) apart
    from "couldn't check" (leave previous value untouched, worth retrying next run).
    """
    headers = {"apiKey": nvd_api_key()} if nvd_api_key() else {}
    payload = _get_json(NVD_URL, params={"cveId": cve_id}, headers=headers)
    vulnerabilities = payload.get("vulnerabilities") or []
    if not vulnerabilities:
        return None
    metrics = vulnerabilities[0].get("cve", {}).get("metrics", {})
    for metric_key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(metric_key) or []
        if not entries:
            continue
        primary = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        vector = primary.get("cvssData", {}).get("vectorString")
        if vector:
            return vector
    return None


def enrich_vulnerabilities(
    vulnerabilities: Iterable[Any],
    *,
    sources: frozenset[str] = frozenset({"kev", "epss", "cvss"}),
    force_cvss: bool = False,
    dry_run: bool = False,
) -> dict[str, Any]:
    """
    Fetch KEV/EPSS/CVSS for `vulnerabilities` (an iterable of Vulnerability rows, CVE-type)
    and update their cache columns + enrichment_updated. Each source is independent: a failed
    source is logged and skipped, the others still apply (CLAUDE.md §7).

    KEV is authoritative for known_exploited/kev_date/kev_due_date/ransomware_used once
    checked: absence from the catalog is recorded as known_exploited=False (a confirmed
    "checked, not listed"), not left NULL — same None-vs-False distinction the model
    docstring already draws for "never looked" vs "no signal".

    EPSS is re-fetched and overwritten every run (daily re-scored upstream; there is no
    "gap" semantics for a score that changes).

    CVSS is fetched only for vulnerabilities with no cvssv3_vector yet, unless force_cvss=True
    (NVD's rate limit makes refetching cheap data expensive; a CVE's assigned vector rarely
    changes once published).

    Returns {"kev": {...}, "epss": {...}, "cvss": {...}, "updated": int} where each source's
    dict is {"attempted": bool, "error": str | None, "matched": int}. dry_run=True fetches
    and reports but writes nothing.
    """
    from dojo.vulnerability.models import Vulnerability  # noqa: PLC0415 -- lazy import, see module docstring

    vulnerabilities = list(vulnerabilities)
    cve_ids = [v.vulnerability_id for v in vulnerabilities]
    report: dict[str, Any] = {"kev": {"attempted": False, "error": None, "matched": 0},
                               "epss": {"attempted": False, "error": None, "matched": 0},
                               "cvss": {"attempted": False, "error": None, "matched": 0}}

    kev_catalog: dict[str, dict[str, Any]] = {}
    if "kev" in sources:
        report["kev"]["attempted"] = True
        try:
            kev_catalog = fetch_kev_catalog()
        except EnrichmentSourceError as exc:
            logger.warning("KEV enrichment skipped: %s", exc)
            report["kev"]["error"] = str(exc)

    epss_scores: dict[str, dict[str, float]] = {}
    if "epss" in sources:
        report["epss"]["attempted"] = True
        try:
            epss_scores = fetch_epss_scores(cve_ids)
        except EnrichmentSourceError as exc:
            logger.warning("EPSS enrichment skipped: %s", exc)
            report["epss"]["error"] = str(exc)

    cvss_vectors: dict[str, str] = {}
    cvss_error: str | None = None
    if "cvss" in sources:
        report["cvss"]["attempted"] = True
        due_for_cvss = vulnerabilities if force_cvss else [v for v in vulnerabilities if not v.cvssv3_vector]
        for index, vuln in enumerate(due_for_cvss):
            try:
                vector = fetch_nvd_cvss_vector(vuln.vulnerability_id)
            except EnrichmentSourceError as exc:
                logger.warning("NVD CVSS lookup failed for %s, leaving existing value: %s", vuln.vulnerability_id, exc)
                cvss_error = cvss_error or str(exc)
                continue
            if vector:
                cvss_vectors[vuln.vulnerability_id] = vector
            if index < len(due_for_cvss) - 1:
                time.sleep(nvd_min_interval_seconds())
        report["cvss"]["error"] = cvss_error

    now = None
    to_update: list[Any] = []
    for vuln in vulnerabilities:
        changed = False
        if "kev" in sources and report["kev"]["error"] is None:
            kev_entry = kev_catalog.get(vuln.vulnerability_id)
            new_known_exploited = kev_entry is not None
            if vuln.known_exploited != new_known_exploited:
                changed = True
            vuln.known_exploited = new_known_exploited
            vuln.kev_date = kev_entry.get("kev_date") if kev_entry else None
            vuln.kev_due_date = kev_entry.get("kev_due_date") if kev_entry else None
            vuln.ransomware_used = kev_entry.get("ransomware_used") if kev_entry else None
            if kev_entry is not None:
                report["kev"]["matched"] += 1
        epss_entry = epss_scores.get(vuln.vulnerability_id)
        if epss_entry is not None:
            vuln.epss_score = epss_entry["epss_score"]
            vuln.epss_percentile = epss_entry["epss_percentile"]
            report["epss"]["matched"] += 1
            changed = True
        cvss_vector = cvss_vectors.get(vuln.vulnerability_id)
        if cvss_vector is not None:
            vuln.cvssv3_vector = cvss_vector
            report["cvss"]["matched"] += 1
            changed = True
        if changed:
            if now is None:
                from django.utils import timezone  # noqa: PLC0415 -- lazy import, see module docstring
                now = timezone.now()
            vuln.enrichment_updated = now
            to_update.append(vuln)

    report["updated"] = len(to_update)
    if to_update and not dry_run:
        Vulnerability.objects.bulk_update(
            to_update,
            fields=["known_exploited", "kev_date", "kev_due_date", "ransomware_used",
                    "epss_score", "epss_percentile", "cvssv3_vector", "enrichment_updated"],
            batch_size=500,
        )
    return report


def project_enrichment_to_findings(vulnerabilities: Iterable[Any], *, force: bool = False) -> dict[str, int]:
    """
    Copy each enriched Vulnerability's cache columns onto the Finding rows whose primary id
    (Finding.cve, == the order=0 FindingVulnerabilityReference — see
    dojo/vulnerability/models.py) matches it.

    force=False (default): only fills a Finding field that is currently empty — None for
    epss_score/cvssv3, or Finding.known_exploited's non-nullable False default (which cannot
    distinguish "never checked" from "checked, not exploited" the way Vulnerability.
    known_exploited's nullable False does) — never overwrites a value a scan-report parser
    already set to True/non-empty, which may be more precise/contextual than the global
    per-CVE enrichment value. force=True overwrites unconditionally.

    Uses Finding.objects.bulk_update (not .save()) deliberately: a silent background
    enrichment pass must not trigger Finding.save()'s notification/JIRA-sync/hash_code side
    effects. cvssv3_score is computed here the same way Finding.save() does (via
    dojo.utils.parse_cvss_data) so the two stay consistent despite bypassing save().
    """
    from dojo.models import Finding  # noqa: PLC0415 -- lazy import, see module docstring
    from dojo.utils import parse_cvss_data  # noqa: PLC0415 -- lazy import, see module docstring

    by_cve = {v.vulnerability_id: v for v in vulnerabilities}
    if not by_cve:
        return {"updated": 0}

    findings = list(Finding.objects.filter(cve__in=list(by_cve)))
    to_update = []
    for finding in findings:
        vuln = by_cve.get(finding.cve)
        if vuln is None:
            continue
        changed = False
        if vuln.known_exploited is not None and (force or not finding.known_exploited):
            if finding.known_exploited != vuln.known_exploited:
                changed = True
            finding.known_exploited = vuln.known_exploited
            finding.kev_date = vuln.kev_date
        if vuln.epss_score is not None and (force or finding.epss_score is None):
            finding.epss_score = vuln.epss_score
            finding.epss_percentile = vuln.epss_percentile
            changed = True
        if vuln.cvssv3_vector and (force or not finding.cvssv3):
            cvss_data = parse_cvss_data(vuln.cvssv3_vector)
            if cvss_data.get("cvssv3"):
                finding.cvssv3 = cvss_data["cvssv3"]
                finding.cvssv3_score = cvss_data.get("cvssv3_score")
                changed = True
        if changed:
            to_update.append(finding)

    if to_update:
        Finding.objects.bulk_update(
            to_update,
            fields=["known_exploited", "kev_date", "epss_score", "epss_percentile", "cvssv3", "cvssv3_score"],
            batch_size=500,
        )
    return {"updated": len(to_update)}
