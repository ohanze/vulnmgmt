"""
Bulk-recompute SSVC decisions for existing Findings.

Manual counterpart to dojo.ssvc.services.compute_and_record's per-finding
entrypoint (CLAUDE.md §6.5): none of the automatic recalculation triggers
(new finding, Product attribute change, KEV/EPSS update, tree version
change, override expiry) are wired to a Celery task/signal yet, so this
command is how an existing finding set gets its first/updated SSVCDecision
until that wiring exists.

Safe to re-run: compute_and_record is idempotent, writing a new
SSVCDecision row for a finding only when its inputs or outcome actually
changed since the latest one (§6.5).
"""
from django.core.management.base import BaseCommand

from dojo.models import Finding
from dojo.ssvc import services as ssvc_services


class Command(BaseCommand):
    help = (
        "Recompute SSVC decisions for Findings (all, by default). Idempotent: "
        "only writes a new SSVCDecision row per finding when its inputs or "
        "outcome changed since the last one."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--tree-id", default=ssvc_services.DEFAULT_TREE_ID,
            help=f"SSVC tree id to evaluate against (default: {ssvc_services.DEFAULT_TREE_ID}).",
        )
        parser.add_argument(
            "--finding-id", type=int, action="append", dest="finding_ids", default=None,
            help="Limit to one Finding id. Repeatable.",
        )
        parser.add_argument(
            "--product-id", type=int, default=None,
            help="Limit to Findings under one Product id.",
        )
        parser.add_argument(
            "--dry-run", action="store_true",
            help="Evaluate and report, but do not write any SSVCDecision rows.",
        )

    def handle(self, *args, **options):
        tree_id = options["tree_id"]
        dry_run = options["dry_run"]

        findings = Finding.objects.select_related(
            "test__engagement__product__prod_type",
        ).order_by("id")
        if options["finding_ids"]:
            findings = findings.filter(id__in=options["finding_ids"])
        if options["product_id"]:
            findings = findings.filter(test__engagement__product_id=options["product_id"])

        total = findings.count()
        self.stdout.write(f"SSVC recompute: {total} finding(s), tree={tree_id!r}, dry_run={dry_run}")

        processed = created = unchanged = needs_review = errors = 0
        for finding in findings.iterator(chunk_size=500):
            processed += 1
            try:
                if dry_run:
                    result = ssvc_services.evaluate_finding(finding, tree_id=tree_id)
                    if result["needs_review"]:
                        needs_review += 1
                else:
                    decision, was_created = ssvc_services.compute_and_record(finding, tree_id=tree_id)
                    if was_created:
                        created += 1
                    else:
                        unchanged += 1
                    if decision.needs_review:
                        needs_review += 1
            except ssvc_services.SSVCTreeError as exc:
                errors += 1
                self.stderr.write(f"finding {finding.id}: {exc}")

            if processed % 500 == 0 or processed == total:
                self.stdout.write(f"... {processed}/{total}")

        self.stdout.write(
            f"Done: processed={processed} created={created} unchanged={unchanged} "
            f"needs_review={needs_review} errors={errors}",
        )
