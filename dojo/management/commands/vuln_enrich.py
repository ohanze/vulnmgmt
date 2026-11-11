"""
Enrich the Vulnerability cache (and, by default, Findings) with CVSS vectors and exploit
signals pulled directly from public sources — CISA KEV, FIRST.org EPSS, NVD API 2.0.

Manual counterpart to dojo.vuln_enrichment.services (CLAUDE.md §7): no Celery beat entry or
import-time trigger calls this yet (same gap noted on dojo.ssvc.services.compute_and_record /
manage.py ssvc_recompute), so this command is how the Vulnerability/Finding enrichment columns
get their first/updated values until that wiring exists. Safe to re-run: both
enrich_vulnerabilities and project_enrichment_to_findings only write rows whose values actually
changed (or, for Findings, only fill gaps unless --force-project).

Typical use: run this, then `manage.py ssvc_recompute` — the SSVC engine reads the Finding
columns this command fills (known_exploited, epss_score, cvssv3).
"""
from django.core.management.base import BaseCommand

from dojo.vuln_enrichment import services as enrichment_services
from dojo.vulnerability.models import Vulnerability

ALL_SOURCES = frozenset({"kev", "epss", "cvss"})


class Command(BaseCommand):
    help = (
        "Fetch CVSS (NVD API 2.0), KEV, and EPSS data from public sources for CVE-type "
        "Vulnerability rows, then project the results onto matching Findings (default: "
        "gap-fill only)."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--source", action="append", dest="sources", choices=sorted(ALL_SOURCES), default=None,
            help="Limit to one enrichment source. Repeatable. Default: kev, epss, and cvss.",
        )
        parser.add_argument(
            "--cve", action="append", dest="cve_ids", default=None,
            help="Limit to one CVE id. Repeatable.",
        )
        parser.add_argument(
            "--product-id", type=int, default=None,
            help="Limit to CVEs referenced by Findings under one Product id.",
        )
        parser.add_argument(
            "--force-cvss", action="store_true",
            help="Re-fetch CVSS from NVD even for vulnerabilities that already have a vector.",
        )
        parser.add_argument(
            "--force-project", action="store_true",
            help="Overwrite a Finding's own epss_score/known_exploited/cvssv3 even if already set, "
                 "instead of only filling gaps.",
        )
        parser.add_argument(
            "--skip-project", action="store_true",
            help="Update the Vulnerability cache only; do not touch Finding rows.",
        )
        parser.add_argument(
            "--dry-run", action="store_true",
            help="Fetch and report, but write nothing.",
        )

    def handle(self, *args, **options):
        sources = frozenset(options["sources"]) if options["sources"] else ALL_SOURCES
        dry_run = options["dry_run"]

        vulnerabilities = Vulnerability.objects.filter(vulnerability_id_type="CVE")
        if options["cve_ids"]:
            vulnerabilities = vulnerabilities.filter(vulnerability_id__in=options["cve_ids"])
        if options["product_id"]:
            vulnerabilities = vulnerabilities.filter(
                finding_references__finding__test__engagement__product_id=options["product_id"],
            ).distinct()
        vulnerabilities = list(vulnerabilities)

        self.stdout.write(
            f"vuln_enrich: {len(vulnerabilities)} CVE(s), sources={sorted(sources)}, dry_run={dry_run}",
        )
        if not vulnerabilities:
            self.stdout.write("Nothing to do.")
            return

        report = enrichment_services.enrich_vulnerabilities(
            vulnerabilities,
            sources=sources,
            force_cvss=options["force_cvss"],
            dry_run=dry_run,
        )
        for source in ("kev", "epss", "cvss"):
            info = report[source]
            if not info["attempted"]:
                continue
            status = f"error: {info['error']}" if info["error"] else f"matched {info['matched']}"
            self.stdout.write(f"  {source}: {status}")
        self.stdout.write(f"Vulnerability rows updated: {report['updated']}")

        if options["skip_project"]:
            return
        if dry_run:
            self.stdout.write("Finding projection skipped (--dry-run).")
            return

        project_report = enrichment_services.project_enrichment_to_findings(
            vulnerabilities, force=options["force_project"],
        )
        self.stdout.write(f"Finding rows updated: {project_report['updated']}")
