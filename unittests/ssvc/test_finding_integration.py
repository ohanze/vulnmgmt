"""
Testy warstwy integracji silnika SSVC z Finding/Product (CLAUDE.md
§6.2/§6.4/§6.5): heurystyki Exploitation/Automatable/Technical Impact,
złożenie wejść (build_finding_inputs), ewaluacja end-to-end i
idempotentny zapis SSVCDecision (compute_and_record).
"""
import os
from unittest import mock

from django.utils.timezone import now

from dojo.models import Dojo_User, Engagement, Finding, Product, Product_Type, Test, Test_Type
from dojo.ssvc import services as ssvc_services
from dojo.ssvc.models import SSVCDecision
from unittests.dojo_test_case import DojoTestCase

CVSS_AUTOMATABLE_TOTAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
CVSS_NOT_AUTOMATABLE_PARTIAL = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N"


class TestFindingIntegration(DojoTestCase):

    @classmethod
    def setUpTestData(cls):
        cls.user = Dojo_User.objects.create(username="ssvc_fi_user")
        cls.prod_type = Product_Type.objects.create(name="SSVC FI Product Type")
        cls.product = Product.objects.create(
            name="SSVC FI Product", prod_type=cls.prod_type, description="SSVC FI Product",
            ssvc_exposure="controlled", ssvc_mission_impact="supportive", ssvc_safety_impact="none",
            ssvc_context_verified=True,
        )
        cls.engagement = Engagement.objects.create(
            name="SSVC FI Engagement", product=cls.product, target_start=now(), target_end=now(),
        )
        cls.test_type = Test_Type.objects.create(name="SSVC FI Test Type")
        cls.test = Test.objects.create(
            title="SSVC FI Test", engagement=cls.engagement, test_type=cls.test_type,
            target_start=now(), target_end=now(),
        )

    def _make_finding(self, **kwargs):
        defaults = {"title": "SSVC FI Finding", "test": self.test, "reporter": self.user, "severity": "High"}
        defaults.update(kwargs)
        return Finding.objects.create(**defaults)

    # -- derive_exploitation --------------------------------------------

    def test_derive_exploitation_known_exploited(self):
        finding = self._make_finding(known_exploited=True, cve="CVE-2026-1")
        value, provenance, needs_review = ssvc_services.derive_exploitation(finding)
        self.assertEqual(value, "active")
        self.assertEqual(provenance["source"], "auto:known_exploited")
        self.assertFalse(needs_review)

    def test_derive_exploitation_no_kev_match_with_cve(self):
        """CVE jest, ale brak w KEV -> realne 'none', nie brakujące dane."""
        finding = self._make_finding(known_exploited=False, cve="CVE-2026-2")
        value, provenance, needs_review = ssvc_services.derive_exploitation(finding)
        self.assertEqual(value, "none")
        self.assertEqual(provenance["source"], "auto:no_kev_match")
        self.assertFalse(needs_review)

    def test_derive_exploitation_epss_above_threshold_gives_poc(self):
        finding = self._make_finding(known_exploited=False, cve="CVE-2026-3", epss_score=0.15)
        value, provenance, needs_review = ssvc_services.derive_exploitation(finding)
        self.assertEqual(value, "poc")
        self.assertEqual(provenance["source"], "auto:epss_threshold")
        self.assertEqual(provenance["epss_score"], 0.15)
        self.assertFalse(needs_review)

    def test_derive_exploitation_epss_below_threshold_with_cve_gives_none(self):
        finding = self._make_finding(known_exploited=False, cve="CVE-2026-4", epss_score=0.02)
        value, _provenance, needs_review = ssvc_services.derive_exploitation(finding)
        self.assertEqual(value, "none")
        self.assertFalse(needs_review)

    def test_derive_exploitation_known_exploited_wins_over_epss(self):
        finding = self._make_finding(known_exploited=True, cve="CVE-2026-5", epss_score=0.01)
        value, provenance, _needs_review = ssvc_services.derive_exploitation(finding)
        self.assertEqual(value, "active")
        self.assertEqual(provenance["source"], "auto:known_exploited")

    def test_derive_exploitation_epss_threshold_configurable_via_env(self):
        finding = self._make_finding(known_exploited=False, cve="CVE-2026-6", epss_score=0.3)
        with mock.patch.dict(os.environ, {"DD_SSVC_EPSS_POC_THRESHOLD": "0.5"}):
            value, _provenance, _needs_review = ssvc_services.derive_exploitation(finding)
        self.assertEqual(value, "none")  # 0.3 < 0.5 z nadpisanym progiem

    def test_derive_exploitation_invalid_threshold_env_falls_back_to_default(self):
        finding = self._make_finding(known_exploited=False, cve="CVE-2026-7", epss_score=0.3)
        with mock.patch.dict(os.environ, {"DD_SSVC_EPSS_POC_THRESHOLD": "not-a-float"}):
            value, _provenance, _needs_review = ssvc_services.derive_exploitation(finding)
        self.assertEqual(value, "poc")  # 0.3 >= domyslny prog 0.1, zly env nie wywala

    def test_derive_exploitation_no_cve_defaults_conservative_and_flags(self):
        """Brak CVE (SAST/DAST/pentest) -> KEV nigdy nie mógł zostać sprawdzony: konserwatywne 'active' + needs_review."""
        finding = self._make_finding(known_exploited=False, cve=None)
        value, provenance, needs_review = ssvc_services.derive_exploitation(finding)
        self.assertEqual(value, "active")
        self.assertEqual(provenance["source"], "default:no_cve")
        self.assertTrue(needs_review)

    # -- derive_automatable ------------------------------------------------

    def test_derive_automatable_from_cvss_vector(self):
        finding = self._make_finding(cvssv3=CVSS_AUTOMATABLE_TOTAL)
        value, provenance, needs_review = ssvc_services.derive_automatable(finding)
        self.assertEqual(value, "yes")
        self.assertFalse(needs_review)
        self.assertEqual(provenance["source"], "auto:cvssv3_vector")

    def test_derive_automatable_not_automatable_from_cvss_vector(self):
        finding = self._make_finding(cvssv3=CVSS_NOT_AUTOMATABLE_PARTIAL)
        value, _provenance, needs_review = ssvc_services.derive_automatable(finding)
        self.assertEqual(value, "no")
        self.assertFalse(needs_review)

    def test_derive_automatable_no_cvss_defaults_conservative_and_flags(self):
        finding = self._make_finding(cvssv3=None)
        value, provenance, needs_review = ssvc_services.derive_automatable(finding)
        self.assertEqual(value, "yes")
        self.assertTrue(needs_review)
        self.assertEqual(provenance["source"], "default:no_cvss3_vector")

    # -- derive_technical_impact --------------------------------------------

    def test_derive_technical_impact_total_from_cvss_vector(self):
        finding = self._make_finding(cvssv3=CVSS_AUTOMATABLE_TOTAL)
        value, _provenance, needs_review = ssvc_services.derive_technical_impact(finding)
        self.assertEqual(value, "total")
        self.assertFalse(needs_review)

    def test_derive_technical_impact_partial_from_cvss_vector(self):
        finding = self._make_finding(cvssv3=CVSS_NOT_AUTOMATABLE_PARTIAL)
        value, _provenance, needs_review = ssvc_services.derive_technical_impact(finding)
        self.assertEqual(value, "partial")
        self.assertFalse(needs_review)

    def test_derive_technical_impact_no_cvss_defaults_conservative_and_flags(self):
        finding = self._make_finding(cvssv3=None)
        value, provenance, needs_review = ssvc_services.derive_technical_impact(finding)
        self.assertEqual(value, "total")
        self.assertTrue(needs_review)
        self.assertEqual(provenance["source"], "default:no_cvss3_vector")

    # -- build_finding_inputs ------------------------------------------------

    def test_build_finding_inputs_pulls_asset_context_from_product(self):
        finding = self._make_finding(cvssv3=CVSS_AUTOMATABLE_TOTAL, known_exploited=True)
        values, provenance, needs_review = ssvc_services.build_finding_inputs(finding)

        self.assertEqual(values["exposure"], "controlled")
        self.assertEqual(values["mission_impact"], "supportive")
        self.assertEqual(values["safety_impact"], "none")
        self.assertEqual(provenance["exposure"]["source"], "product")
        # product.ssvc_context_verified=True i pełny wektor CVSS -> nic do przeglądu
        self.assertFalse(needs_review)

    def test_build_finding_inputs_unverified_product_context_sets_needs_review(self):
        unverified_product = Product.objects.create(
            name="SSVC FI Unverified Product", prod_type=self.prod_type, description="unverified",
        )
        engagement = Engagement.objects.create(
            name="SSVC FI Unverified Engagement", product=unverified_product, target_start=now(), target_end=now(),
        )
        test = Test.objects.create(
            title="SSVC FI Unverified Test", engagement=engagement, test_type=self.test_type,
            target_start=now(), target_end=now(),
        )
        finding = Finding.objects.create(
            title="Unverified product finding", test=test, reporter=self.user, severity="High",
            cvssv3=CVSS_AUTOMATABLE_TOTAL,
        )

        _values, _provenance, needs_review = ssvc_services.build_finding_inputs(finding)
        self.assertTrue(needs_review)

    # -- evaluate_finding / compute_and_record ------------------------------

    def test_evaluate_finding_end_to_end(self):
        finding = self._make_finding(cvssv3=CVSS_AUTOMATABLE_TOTAL, known_exploited=True)
        result = ssvc_services.evaluate_finding(finding)

        # active/yes/total/controlled, criticality=medium (supportive+none z macierzy -> medium)
        self.assertEqual(result["inputs"]["exploitation"], "active")
        self.assertEqual(result["criticality"], "medium")
        self.assertIn(result["outcome"], ("defer", "scheduled", "out_of_cycle", "immediate"))

    def test_compute_and_record_creates_then_is_idempotent(self):
        finding = self._make_finding(cvssv3=CVSS_AUTOMATABLE_TOTAL, known_exploited=True)

        decision1, created1 = ssvc_services.compute_and_record(finding)
        self.assertTrue(created1)
        self.assertEqual(SSVCDecision.objects.filter(finding=finding).count(), 1)

        decision2, created2 = ssvc_services.compute_and_record(finding)
        self.assertFalse(created2)
        self.assertEqual(decision2.pk, decision1.pk)
        self.assertEqual(SSVCDecision.objects.filter(finding=finding).count(), 1)

    def test_compute_and_record_creates_new_row_when_inputs_change(self):
        finding = self._make_finding(cvssv3=CVSS_AUTOMATABLE_TOTAL, known_exploited=False, cve="CVE-2026-3")
        decision1, _ = ssvc_services.compute_and_record(finding)

        finding.known_exploited = True
        finding.save()
        decision2, created2 = ssvc_services.compute_and_record(finding)

        self.assertTrue(created2)
        self.assertNotEqual(decision2.pk, decision1.pk)
        self.assertEqual(SSVCDecision.objects.filter(finding=finding).count(), 2)
        # historia pierwszej decyzji musi zostac, nie jest nadpisywana
        decision1.refresh_from_db()
        self.assertEqual(decision1.exploitation, "none")

    # -- immutability ---------------------------------------------------

    def test_ssvc_decision_cannot_be_updated(self):
        finding = self._make_finding()
        decision, _ = ssvc_services.compute_and_record(finding)
        decision.outcome = "immediate"
        with self.assertRaises(ValueError):
            decision.save()

    def test_ssvc_decision_cannot_be_deleted_directly(self):
        finding = self._make_finding()
        decision, _ = ssvc_services.compute_and_record(finding)
        with self.assertRaises(ValueError):
            decision.delete()
