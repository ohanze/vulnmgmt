"""SSVC decision engine: (tree, decision point values) -> decision.

Two layers in this one file (one services.py per domain, per CLAUDE.md
§4 — not split further):

1. The tree evaluator (load_tree/evaluate/derive_criticality below) is
   deliberately framework-agnostic: no Django imports anywhere in it.
   Trees are data (dojo/ssvc/trees/*.yaml); it only resolves them.

2. The Finding-integration layer (derive_exploitation and friends,
   build_finding_inputs, evaluate_finding, compute_and_record) *does*
   read Django models (Finding, Product) and writes SSVCDecision rows —
   that's unavoidable, it's the glue CLAUDE.md §6.2/§6.4/§6.5 describes.
   It imports Django/dojo.models lazily, inside each function, matching
   the rest of this codebase's convention for domain services (avoids
   circular imports; dojo.ssvc.services itself is importable before the
   app registry is ready, same as before this layer existed).
"""

from __future__ import annotations

import functools
import logging
import os
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

# FIRST.org's commonly cited "significantly elevated" EPSS threshold —
# user-confirmed default (CLAUDE.md §6.2's "EPSS, próg konfigurowalny").
# Override via DD_SSVC_EPSS_POC_THRESHOLD (float, e.g. "0.05"). Read
# directly from the environment, not django.conf.settings: this keeps
# dojo/settings/settings.dist.py untouched (CLAUDE.md §13, minimalna
# integracja) — one more DD_* var there would be an existing-file edit
# for a value this module can own and read itself.
DEFAULT_EPSS_POC_THRESHOLD = 0.1


def epss_poc_threshold() -> float:
    raw = os.environ.get("DD_SSVC_EPSS_POC_THRESHOLD")
    if raw is None:
        return DEFAULT_EPSS_POC_THRESHOLD
    try:
        return float(raw)
    except ValueError:
        logger.warning(
            "Invalid DD_SSVC_EPSS_POC_THRESHOLD=%r, falling back to default %s", raw, DEFAULT_EPSS_POC_THRESHOLD,
        )
        return DEFAULT_EPSS_POC_THRESHOLD

TREES_DIR = Path(__file__).resolve().parent / "trees"

RULE_AXES = ("exploitation", "automatable", "technical_impact", "exposure")
REQUIRED_INPUTS = (*RULE_AXES, "mission_impact", "safety_impact")


class SSVCTreeError(Exception):
    """Raised when a tree definition is malformed, or evaluate() inputs don't match it."""


@functools.lru_cache(maxsize=None)
def load_tree(tree_id: str) -> dict[str, Any]:
    """Load and cache a tree definition by id (its filename, without .yaml)."""
    path = TREES_DIR / f"{tree_id}.yaml"
    if not path.is_file():
        raise SSVCTreeError(f"Unknown SSVC tree id: {tree_id!r} (looked for {path})")
    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f)


def available_trees() -> list[str]:
    return sorted(p.stem for p in TREES_DIR.glob("*.yaml"))


def _check_value(tree: dict[str, Any], point_id: str, value: str) -> None:
    point = tree["decision_points"].get(point_id)
    if point is None:
        raise SSVCTreeError(f"Tree {tree['id']!r} has no decision point {point_id!r}")
    if value not in point["values"]:
        raise SSVCTreeError(
            f"Invalid value {value!r} for decision point {point_id!r} in tree {tree['id']!r}; "
            f"expected one of {point['values']}",
        )


def derive_criticality(tree: dict[str, Any], mission_impact: str, safety_impact: str) -> str:
    """"Istotność systemu dla organizacji" = f(mission_impact, safety_impact), per the tree's matrix."""
    _check_value(tree, "mission_impact", mission_impact)
    _check_value(tree, "safety_impact", safety_impact)
    return tree["mission_criticality_matrix"][mission_impact][safety_impact]


def evaluate(tree: dict[str, Any], values: dict[str, str]) -> dict[str, Any]:
    """
    Evaluate one SSVC decision against `tree`.

    `values` must provide all of REQUIRED_INPUTS, using the English value
    codes declared under the tree's `decision_points` (e.g.
    exploitation="active", not "Aktywna" — labels are for display only).

    Returns a plain dict (tree_id, tree_version, criticality, outcome,
    inputs) — not an ORM object. Raises SSVCTreeError on missing/invalid
    inputs or (should the table ever be incomplete) an unmatched rule.
    """
    missing = [k for k in REQUIRED_INPUTS if k not in values]
    if missing:
        raise SSVCTreeError(f"Missing decision point value(s): {missing}")

    for point_id in RULE_AXES:
        _check_value(tree, point_id, values[point_id])

    criticality = derive_criticality(tree, values["mission_impact"], values["safety_impact"])

    for rule in tree["decision_table"]:
        when = rule["when"]
        if all(when[point_id] == values[point_id] for point_id in RULE_AXES):
            return {
                "tree_id": tree["id"],
                "tree_version": tree["version"],
                "criticality": criticality,
                "outcome": rule["outcomes"][criticality],
                "inputs": dict(values),
            }

    raise SSVCTreeError(
        f"No matching rule in tree {tree['id']!r} for "
        f"exploitation={values['exploitation']!r}, automatable={values['automatable']!r}, "
        f"technical_impact={values['technical_impact']!r}, exposure={values['exposure']!r}",
    )


# ---------------------------------------------------------------------------
# Finding integration (CLAUDE.md §6.2/§6.4): derive the three Finding-level
# decision points from data already on Finding, plus the three asset-level
# ones from its Product. "Brak danych -> wartość konserwatywna + flaga, nigdy
# ciche pominięcie" (§6.4) — every derive_* below returns a needs_review bit
# precisely for the "we had to guess" case, never silently.
# ---------------------------------------------------------------------------

DEFAULT_TREE_ID = "org_custom_v1"


def derive_exploitation(finding: Any) -> tuple[str, dict[str, Any], bool]:
    """
    Exploitation from Finding.known_exploited (CLAUDE.md §6.2: map
    known_exploited=True -> Active as the starting point; KEV already
    populates this field, so no new KEV integration is built here) and
    Finding.epss_score against epss_poc_threshold() for the PoC tier.

    "none" on no KEV match and EPSS below threshold is a legitimate
    determination *only when the finding has a CVE* — both were
    actually checkable and came back clean/low, not missing data, so
    needs_review stays False for that case.

    A finding with no CVE at all (SAST/DAST/pentest) could never have
    been checked against KEV or EPSS in the first place: both
    known_exploited and epss_score are just their untouched defaults
    there. Per §6.4 ("Exploitation i Automatable domyślnie z reguł
    mapowania... Brak danych -> konserwatywna + flaga, nigdy ciche
    pominięcie"), that's the conservative-default case, same as
    derive_automatable/derive_technical_impact below — not the same as
    a real "none". The per-scanner-type mapping rules §6.4 also
    describes (confirmed pentest exploit = Active, confirmed Nuclei
    response = PoC) aren't implemented here, same gap noted on
    derive_automatable.
    """
    if finding.known_exploited:
        return "active", {"source": "auto:known_exploited"}, False
    threshold = epss_poc_threshold()
    if finding.epss_score is not None and finding.epss_score >= threshold:
        provenance = {"source": "auto:epss_threshold", "epss_score": finding.epss_score, "threshold": threshold}
        return "poc", provenance, False
    if finding.cve:
        return "none", {"source": "auto:no_kev_match"}, False
    return "active", {"source": "default:no_cve"}, True


def _cvss3_metrics(cvssv3_vector: str | None) -> dict[str, str] | None:
    """{"AV": "N", "AC": "L", ...} from a cvssv3 vector string, or None if unusable."""
    if not cvssv3_vector:
        return None
    from cvss import CVSS3  # noqa: PLC0415 -- lazy import, see module docstring

    try:
        return CVSS3(cvssv3_vector).metrics
    except Exception:
        logger.warning("Could not parse cvssv3 vector for SSVC derivation: %r", cvssv3_vector)
        return None


def derive_automatable(finding: Any) -> tuple[str, dict[str, Any], bool]:
    """
    Automatable from the CVSSv3 vector (CLAUDE.md §6.2: AV:N, AC:L, PR:N,
    UI:N -> Yes). Only cvssv3 is read — cvssv4 uses a different metric
    set (AT, VC/VI/VA, ...) and isn't mapped here, that's a gap, not an
    oversight.

    No usable CVSSv3 vector (no CVE, e.g. SAST/DAST/pentest findings) ->
    conservative "yes" + needs_review=True. §6.4 also describes
    per-scanner-type heuristics (confirmed exploit in a pentest, a
    Nuclei finding with a confirmed response) — not implemented: there's
    no verified Finding field yet that reliably encodes "confirmed" for
    those tools, and CLAUDE.md's own rule is not to invent that mapping.
    """
    metrics = _cvss3_metrics(finding.cvssv3)
    if metrics is None:
        return "yes", {"source": "default:no_cvss3_vector"}, True
    required_metrics = (("AV", "N"), ("AC", "L"), ("PR", "N"), ("UI", "N"))
    automatable = all(metrics.get(k) == expected for k, expected in required_metrics)
    provenance = {"source": "auto:cvssv3_vector", "vector": finding.cvssv3}
    return ("yes" if automatable else "no"), provenance, False


def derive_technical_impact(finding: Any) -> tuple[str, dict[str, Any], bool]:
    """
    Technical Impact from the CVSSv3 vector's C/I/A metrics (CLAUDE.md
    §6.2): any of Confidentiality/Integrity/Availability = High -> Total.
    Same cvssv3-only, same no-CWE-heuristic limitations as
    derive_automatable above (no concrete CWE->impact rule is given in
    CLAUDE.md to implement).

    No usable vector -> conservative "total" + needs_review=True.
    """
    metrics = _cvss3_metrics(finding.cvssv3)
    if metrics is None:
        return "total", {"source": "default:no_cvss3_vector"}, True
    total = metrics.get("C") == "H" or metrics.get("I") == "H" or metrics.get("A") == "H"
    provenance = {"source": "auto:cvssv3_vector", "vector": finding.cvssv3}
    return ("total" if total else "partial"), provenance, False


def build_finding_inputs(finding: Any) -> tuple[dict[str, str], dict[str, dict[str, Any]], bool]:
    """
    (values, provenance, needs_review) for evaluate(), for one Finding.

    Exposure/Mission Impact/Safety Impact come from
    finding.test.engagement.product.ssvc_asset_context() (Product >
    Product_Type > conservative default, each resolved once —
    dojo/product/models.py). An unverified asset context
    (Product.ssvc_context_verified=False) folds into needs_review here
    too, so "this decision rests on an unconfirmed asset guess" is
    visible on the SSVCDecision itself, per §6.3's "flagę
    'niezweryfikowane', widoczną na decyzji SSVC" — not just on the
    Product.
    """
    product = finding.test.engagement.product
    asset_context = product.ssvc_asset_context()

    exploitation, exploitation_prov, exploitation_needs_review = derive_exploitation(finding)
    automatable, automatable_prov, automatable_needs_review = derive_automatable(finding)
    technical_impact, technical_impact_prov, technical_impact_needs_review = derive_technical_impact(finding)

    values = {
        "exploitation": exploitation,
        "automatable": automatable,
        "technical_impact": technical_impact,
        "exposure": asset_context["exposure"],
        "mission_impact": asset_context["mission_impact"],
        "safety_impact": asset_context["safety_impact"],
    }
    provenance = {
        "exploitation": exploitation_prov,
        "automatable": automatable_prov,
        "technical_impact": technical_impact_prov,
        "exposure": {"source": asset_context["exposure_source"]},
        "mission_impact": {"source": asset_context["mission_impact_source"]},
        "safety_impact": {"source": asset_context["safety_impact_source"]},
    }
    needs_review = (
        exploitation_needs_review
        or automatable_needs_review
        or technical_impact_needs_review
        or not product.ssvc_context_verified
    )
    return values, provenance, needs_review


def evaluate_finding(finding: Any, *, tree_id: str = DEFAULT_TREE_ID) -> dict[str, Any]:
    """Compute (does not persist) a full SSVC decision dict for one Finding."""
    tree = load_tree(tree_id)
    values, provenance, needs_review = build_finding_inputs(finding)
    result = evaluate(tree, values)
    result["provenance"] = provenance
    result["needs_review"] = needs_review
    return result


def compute_and_record(finding: Any, *, tree_id: str = DEFAULT_TREE_ID) -> tuple[Any, bool]:
    """
    Evaluate `finding` and persist a new SSVCDecision — but only if its
    inputs or outcome differ from the most recent existing decision for
    this Finding (CLAUDE.md §6.5: recalculation is idempotent). Returns
    (decision, created); created=False means the existing latest record
    was returned untouched, no row was written.

    No Celery task calls this yet (the recalculation triggers in §6.5 —
    new finding, Product attribute change, KEV/EPSS update, tree version
    change, override expiry — aren't wired up); this is the synchronous
    entrypoint a future task would call per finding_id.
    """
    from dojo.ssvc.models import SSVCDecision  # noqa: PLC0415 -- lazy import, see module docstring

    result = evaluate_finding(finding, tree_id=tree_id)
    inputs = result["inputs"]

    latest = finding.ssvc_decisions.first()  # Meta.ordering = ("-created",)
    if (
        latest is not None
        and latest.tree_id == result["tree_id"]
        and latest.tree_version == result["tree_version"]
        and latest.outcome == result["outcome"]
        and latest.exploitation == inputs["exploitation"]
        and latest.automatable == inputs["automatable"]
        and latest.technical_impact == inputs["technical_impact"]
        and latest.exposure == inputs["exposure"]
        and latest.mission_impact == inputs["mission_impact"]
        and latest.safety_impact == inputs["safety_impact"]
    ):
        return latest, False

    decision = SSVCDecision.objects.create(
        finding=finding,
        tree_id=result["tree_id"],
        tree_version=result["tree_version"],
        exploitation=inputs["exploitation"],
        automatable=inputs["automatable"],
        technical_impact=inputs["technical_impact"],
        exposure=inputs["exposure"],
        mission_impact=inputs["mission_impact"],
        safety_impact=inputs["safety_impact"],
        criticality=result["criticality"],
        outcome=result["outcome"],
        provenance=result["provenance"],
        needs_review=result["needs_review"],
    )
    return decision, True
