"""
Tests for dojo.vuln_enrichment.services (CLAUDE.md §7): parsing of the three public sources
(CISA KEV, FIRST EPSS, NVD API 2.0), the enrich/project orchestration, per-source failure
isolation, and gap-fill-only projection onto Finding.
"""
from unittest import mock

import requests
from django.utils.timezone import now

from dojo.models import Dojo_User, Engagement, Finding, Product, Product_Type, Test, Test_Type
from dojo.vuln_enrichment import services as enrichment_services
from dojo.vulnerability.models import Vulnerability
from unittests.dojo_test_case import DojoTestCase

MODULE = "dojo.vuln_enrichment.services"


class TestFetchKevCatalog(DojoTestCase):

    @mock.patch(f"{MODULE}.requests.get")
    def test_parses_entries_keyed_by_cve(self, mock_get):
        mock_get.return_value.json.return_value = {
            "vulnerabilities": [
                {"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10", "dueDate": "2021-12-24",
                 "knownRansomwareCampaignUse": "Known"},
                {"cveID": "CVE-2021-99999", "dateAdded": "2021-01-01", "dueDate": "2021-01-15",
                 "knownRansomwareCampaignUse": "Unknown"},
            ],
        }
        mock_get.return_value.raise_for_status.return_value = None
        catalog = enrichment_services.fetch_kev_catalog()
        self.assertEqual(catalog["CVE-2021-44228"]["kev_date"], "2021-12-10")
        self.assertTrue(catalog["CVE-2021-44228"]["ransomware_used"])
        self.assertFalse(catalog["CVE-2021-99999"]["ransomware_used"])

    @mock.patch(f"{MODULE}.requests.get")
    def test_network_error_raises_enrichment_source_error(self, mock_get):
        mock_get.side_effect = requests.ConnectionError("boom")
        with self.assertRaises(enrichment_services.EnrichmentSourceError):
            enrichment_services.fetch_kev_catalog()


class TestFetchEpssScores(DojoTestCase):

    @mock.patch(f"{MODULE}.requests.get")
    def test_parses_and_batches(self, mock_get):
        mock_get.return_value.json.return_value = {
            "data": [{"cve": "CVE-2026-1", "epss": "0.975910000", "percentile": "0.999660000"}],
        }
        mock_get.return_value.raise_for_status.return_value = None
        scores = enrichment_services.fetch_epss_scores(["CVE-2026-1"])
        self.assertAlmostEqual(scores["CVE-2026-1"]["epss_score"], 0.97591)
        self.assertAlmostEqual(scores["CVE-2026-1"]["epss_percentile"], 0.99966)

    @mock.patch(f"{MODULE}.requests.get")
    def test_batches_requests_by_batch_size(self, mock_get):
        mock_get.return_value.json.return_value = {"data": []}
        mock_get.return_value.raise_for_status.return_value = None
        cve_ids = [f"CVE-2026-{i}" for i in range(250)]
        with mock.patch(f"{MODULE}.EPSS_BATCH_SIZE", 100):
            enrichment_services.fetch_epss_scores(cve_ids)
        self.assertEqual(mock_get.call_count, 3)  # 100 + 100 + 50

    @mock.patch(f"{MODULE}.requests.get")
    def test_skips_unparseable_row_without_raising(self, mock_get):
        mock_get.return_value.json.return_value = {"data": [{"cve": "CVE-2026-1", "epss": "not-a-number"}]}
        mock_get.return_value.raise_for_status.return_value = None
        scores = enrichment_services.fetch_epss_scores(["CVE-2026-1"])
        self.assertEqual(scores, {})


class TestFetchNvdCvssVector(DojoTestCase):

    @mock.patch(f"{MODULE}.requests.get")
    def test_prefers_v31_primary_over_secondary(self, mock_get):
        mock_get.return_value.json.return_value = {
            "vulnerabilities": [{"cve": {"metrics": {
                "cvssMetricV31": [
                    {"type": "Secondary", "cvssData": {"vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L"}},
                    {"type": "Primary", "cvssData": {"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
                ],
            }}}],
        }
        mock_get.return_value.raise_for_status.return_value = None
        vector = enrichment_services.fetch_nvd_cvss_vector("CVE-2021-44228")
        self.assertEqual(vector, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    @mock.patch(f"{MODULE}.requests.get")
    def test_falls_back_to_v30_when_no_v31(self, mock_get):
        mock_get.return_value.json.return_value = {
            "vulnerabilities": [{"cve": {"metrics": {
                "cvssMetricV30": [{"type": "Primary", "cvssData": {"vectorString": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}],
            }}}],
        }
        mock_get.return_value.raise_for_status.return_value = None
        vector = enrichment_services.fetch_nvd_cvss_vector("CVE-2021-1")
        self.assertEqual(vector, "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    @mock.patch(f"{MODULE}.requests.get")
    def test_no_metrics_returns_none_not_error(self, mock_get):
        mock_get.return_value.json.return_value = {"vulnerabilities": [{"cve": {"metrics": {}}}]}
        mock_get.return_value.raise_for_status.return_value = None
        self.assertIsNone(enrichment_services.fetch_nvd_cvss_vector("CVE-2021-1"))

    @mock.patch(f"{MODULE}.requests.get")
    def test_no_results_returns_none(self, mock_get):
        mock_get.return_value.json.return_value = {"vulnerabilities": []}
        mock_get.return_value.raise_for_status.return_value = None
        self.assertIsNone(enrichment_services.fetch_nvd_cvss_vector("CVE-2021-1"))


class TestEnrichVulnerabilities(DojoTestCase):

    def setUp(self):
        self.vuln_kev = Vulnerability.objects.create(vulnerability_id="CVE-2026-1", vulnerability_id_type="CVE")
        self.vuln_no_kev = Vulnerability.objects.create(vulnerability_id="CVE-2026-2", vulnerability_id_type="CVE")

    @mock.patch(f"{MODULE}.fetch_nvd_cvss_vector")
    @mock.patch(f"{MODULE}.fetch_epss_scores")
    @mock.patch(f"{MODULE}.fetch_kev_catalog")
    def test_applies_all_three_sources_and_persists(self, mock_kev, mock_epss, mock_cvss):
        mock_kev.return_value = {"CVE-2026-1": {"kev_date": "2026-01-01", "kev_due_date": "2026-01-15", "ransomware_used": True}}
        mock_epss.return_value = {
            "CVE-2026-1": {"epss_score": 0.9, "epss_percentile": 0.99},
            "CVE-2026-2": {"epss_score": 0.01, "epss_percentile": 0.1},
        }
        mock_cvss.return_value = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

        report = enrichment_services.enrich_vulnerabilities([self.vuln_kev, self.vuln_no_kev])

        self.vuln_kev.refresh_from_db()
        self.vuln_no_kev.refresh_from_db()
        self.assertTrue(self.vuln_kev.known_exploited)
        self.assertTrue(self.vuln_kev.ransomware_used)
        self.assertEqual(self.vuln_kev.epss_score, 0.9)
        self.assertIsNotNone(self.vuln_kev.cvssv3_vector)
        # Confirmed-checked-and-absent, not left NULL:
        self.assertIs(self.vuln_no_kev.known_exploited, False)
        self.assertIsNotNone(self.vuln_no_kev.enrichment_updated)
        self.assertEqual(report["updated"], 2)

    @mock.patch(f"{MODULE}.fetch_nvd_cvss_vector")
    @mock.patch(f"{MODULE}.fetch_epss_scores")
    @mock.patch(f"{MODULE}.fetch_kev_catalog")
    def test_kev_failure_does_not_block_epss_or_cvss(self, mock_kev, mock_epss, mock_cvss):
        mock_kev.side_effect = enrichment_services.EnrichmentSourceError("CISA is down")
        mock_epss.return_value = {"CVE-2026-1": {"epss_score": 0.5, "epss_percentile": 0.5}}
        mock_cvss.return_value = None

        report = enrichment_services.enrich_vulnerabilities([self.vuln_kev])

        self.vuln_kev.refresh_from_db()
        self.assertIsNotNone(report["kev"]["error"])
        self.assertIsNone(self.vuln_kev.known_exploited)  # untouched default, not flipped by the failed source
        self.assertEqual(self.vuln_kev.epss_score, 0.5)  # other sources still applied

    @mock.patch(f"{MODULE}.fetch_nvd_cvss_vector")
    @mock.patch(f"{MODULE}.fetch_epss_scores")
    @mock.patch(f"{MODULE}.fetch_kev_catalog")
    def test_dry_run_writes_nothing(self, mock_kev, mock_epss, mock_cvss):
        mock_kev.return_value = {}
        mock_epss.return_value = {"CVE-2026-1": {"epss_score": 0.5, "epss_percentile": 0.5}}
        mock_cvss.return_value = None

        enrichment_services.enrich_vulnerabilities([self.vuln_kev], dry_run=True)

        self.vuln_kev.refresh_from_db()
        self.assertIsNone(self.vuln_kev.epss_score)

    @mock.patch(f"{MODULE}.fetch_nvd_cvss_vector")
    def test_cvss_skips_vulnerabilities_that_already_have_a_vector_unless_forced(self, mock_cvss):
        self.vuln_kev.cvssv3_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
        self.vuln_kev.save()
        mock_cvss.return_value = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

        enrichment_services.enrich_vulnerabilities([self.vuln_kev], sources=frozenset({"cvss"}))
        mock_cvss.assert_not_called()

        enrichment_services.enrich_vulnerabilities([self.vuln_kev], sources=frozenset({"cvss"}), force_cvss=True)
        mock_cvss.assert_called_once_with("CVE-2026-1")


class TestProjectEnrichmentToFindings(DojoTestCase):

    @classmethod
    def setUpTestData(cls):
        cls.user = Dojo_User.objects.create(username="vuln_enrich_user")
        cls.prod_type = Product_Type.objects.create(name="Vuln Enrich Product Type")
        cls.product = Product.objects.create(name="Vuln Enrich Product", prod_type=cls.prod_type, description="x")
        cls.engagement = Engagement.objects.create(
            name="Vuln Enrich Engagement", product=cls.product, target_start=now(), target_end=now(),
        )
        cls.test_type = Test_Type.objects.create(name="Vuln Enrich Test Type")
        cls.test = Test.objects.create(
            title="Vuln Enrich Test", engagement=cls.engagement, test_type=cls.test_type,
            target_start=now(), target_end=now(),
        )

    def _make_finding(self, **kwargs):
        defaults = {"title": "Vuln Enrich Finding", "test": self.test, "reporter": self.user, "severity": "High"}
        defaults.update(kwargs)
        return Finding.objects.create(**defaults)

    def _make_vuln(self, cve_id, **kwargs):
        return Vulnerability.objects.create(vulnerability_id=cve_id, vulnerability_id_type="CVE", **kwargs)

    def test_fills_gaps_without_overwriting_parser_supplied_values(self):
        finding = self._make_finding(
            cve="CVE-2026-10",
            cvssv3="CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N",  # already set by a parser
            epss_score=None,
        )
        vuln = self._make_vuln(
            "CVE-2026-10",
            epss_score=0.42, epss_percentile=0.9,
            cvssv3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        )

        report = enrichment_services.project_enrichment_to_findings([vuln])

        finding.refresh_from_db()
        self.assertEqual(finding.epss_score, 0.42)  # gap filled
        self.assertEqual(finding.cvssv3, "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N")  # untouched
        self.assertEqual(report["updated"], 1)

    def test_force_overwrites_existing_finding_values(self):
        finding = self._make_finding(cve="CVE-2026-11", cvssv3="CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N")
        vuln = self._make_vuln("CVE-2026-11", cvssv3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

        enrichment_services.project_enrichment_to_findings([vuln], force=True)

        finding.refresh_from_db()
        self.assertEqual(finding.cvssv3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    def test_does_not_call_finding_save(self):
        """Bulk projection must not trigger Finding.save()'s notification/JIRA-sync side effects."""
        finding = self._make_finding(cve="CVE-2026-12")
        vuln = self._make_vuln("CVE-2026-12", epss_score=0.3, epss_percentile=0.5)

        with mock.patch.object(Finding, "save") as mock_save:
            enrichment_services.project_enrichment_to_findings([vuln])
        mock_save.assert_not_called()

        finding.refresh_from_db()
        self.assertEqual(finding.epss_score, 0.3)

    def test_no_matching_finding_is_a_no_op(self):
        vuln = self._make_vuln("CVE-2026-99", epss_score=0.3)
        report = enrichment_services.project_enrichment_to_findings([vuln])
        self.assertEqual(report["updated"], 0)
