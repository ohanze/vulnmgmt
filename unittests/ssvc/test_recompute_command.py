"""Tests for manage.py ssvc_recompute (dojo/management/commands/ssvc_recompute.py)."""
import io

from django.core.management import call_command
from django.utils.timezone import now

from dojo.models import Dojo_User, Engagement, Finding, Product, Product_Type, Test, Test_Type
from dojo.ssvc.models import SSVCDecision
from unittests.dojo_test_case import DojoTestCase

CVSS_AUTOMATABLE_TOTAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


class TestSsvcRecomputeCommand(DojoTestCase):

    @classmethod
    def setUpTestData(cls):
        cls.user = Dojo_User.objects.create(username="ssvc_recompute_user")
        cls.prod_type = Product_Type.objects.create(name="SSVC Recompute Product Type")
        cls.product_a = Product.objects.create(
            name="SSVC Recompute Product A", prod_type=cls.prod_type, description="A",
            ssvc_exposure="controlled", ssvc_mission_impact="supportive", ssvc_safety_impact="none",
            ssvc_context_verified=True,
        )
        cls.product_b = Product.objects.create(
            name="SSVC Recompute Product B", prod_type=cls.prod_type, description="B",
            ssvc_exposure="controlled", ssvc_mission_impact="supportive", ssvc_safety_impact="none",
            ssvc_context_verified=True,
        )
        cls.test_type = Test_Type.objects.create(name="SSVC Recompute Test Type")
        cls.findings = []
        for product in (cls.product_a, cls.product_a, cls.product_b):
            engagement = Engagement.objects.create(
                name=f"Engagement for {product.name}", product=product, target_start=now(), target_end=now(),
            )
            test = Test.objects.create(
                title=f"Test for {product.name}", engagement=engagement, test_type=cls.test_type,
                target_start=now(), target_end=now(),
            )
            cls.findings.append(Finding.objects.create(
                title="Recompute finding", test=test, reporter=cls.user, severity="High",
                cvssv3=CVSS_AUTOMATABLE_TOTAL, cve="CVE-2026-100",
            ))

    def _run(self, *args):
        out, err = io.StringIO(), io.StringIO()
        call_command("ssvc_recompute", *args, stdout=out, stderr=err)
        return out.getvalue(), err.getvalue()

    def test_recomputes_all_findings_by_default(self):
        out, _err = self._run()
        self.assertIn("3 finding(s)", out)
        self.assertIn("processed=3 created=3", out)
        self.assertEqual(SSVCDecision.objects.count(), 3)

    def test_idempotent_on_second_run(self):
        self._run()
        out, _err = self._run()
        self.assertIn("processed=3 created=0 unchanged=3", out)
        self.assertEqual(SSVCDecision.objects.count(), 3)

    def test_dry_run_writes_nothing(self):
        out, _err = self._run("--dry-run")
        self.assertIn("dry_run=True", out)
        self.assertEqual(SSVCDecision.objects.count(), 0)

    def test_filters_by_product_id(self):
        out, _err = self._run("--product-id", str(self.product_a.id))
        self.assertIn("2 finding(s)", out)
        self.assertEqual(SSVCDecision.objects.count(), 2)

    def test_filters_by_finding_id(self):
        target = self.findings[0]
        out, _err = self._run("--finding-id", str(target.id))
        self.assertIn("1 finding(s)", out)
        self.assertEqual(SSVCDecision.objects.filter(finding=target).count(), 1)
