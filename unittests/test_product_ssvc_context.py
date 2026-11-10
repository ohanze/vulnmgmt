"""
Testy kontekstu assetu dla SSVC na Product/Product_Type
(effective_ssvc_exposure/mission_impact/safety_impact) — CLAUDE.md §6.3:
Product > Product_Type > konserwatywny domyślny (dojo.ssvc.constants).
"""
from dojo.models import Product, Product_Type
from dojo.ssvc import constants as ssvc_constants
from unittests.dojo_test_case import DojoTestCase


class TestProductSSVCContext(DojoTestCase):

    @classmethod
    def setUpTestData(cls):
        cls.prod_type = Product_Type.objects.create(name="SSVC Context Product Type")
        cls.product = Product.objects.create(
            name="SSVC Context Product", prod_type=cls.prod_type, description="SSVC Context Product",
        )

    def test_defaults_to_conservative_when_nothing_set(self):
        self.assertEqual(self.product.effective_ssvc_exposure, ssvc_constants.EXPOSURE_DEFAULT)
        self.assertEqual(self.product.effective_ssvc_mission_impact, ssvc_constants.MISSION_IMPACT_DEFAULT)
        self.assertEqual(self.product.effective_ssvc_safety_impact, ssvc_constants.SAFETY_IMPACT_DEFAULT)
        self.assertFalse(self.product.ssvc_context_verified)

    def test_inherits_from_product_type_when_product_unset(self):
        self.prod_type.ssvc_exposure = ssvc_constants.EXPOSURE_LOCAL
        self.prod_type.ssvc_mission_impact = ssvc_constants.MISSION_IMPACT_MINIMAL
        self.prod_type.save()
        self.product.refresh_from_db()

        self.assertEqual(self.product.effective_ssvc_exposure, ssvc_constants.EXPOSURE_LOCAL)
        self.assertEqual(self.product.effective_ssvc_mission_impact, ssvc_constants.MISSION_IMPACT_MINIMAL)
        # safety_impact wciąż nieustawione na Product_Type -> konserwatywny domyślny
        self.assertEqual(self.product.effective_ssvc_safety_impact, ssvc_constants.SAFETY_IMPACT_DEFAULT)

    def test_products_own_value_overrides_product_type(self):
        self.prod_type.ssvc_exposure = ssvc_constants.EXPOSURE_LOCAL
        self.prod_type.save()
        self.product.ssvc_exposure = ssvc_constants.EXPOSURE_CONTROLLED
        self.product.save()

        self.assertEqual(self.product.effective_ssvc_exposure, ssvc_constants.EXPOSURE_CONTROLLED)

    def test_context_verified_flag_is_plain_boolean(self):
        self.assertFalse(self.product.ssvc_context_verified)
        self.product.ssvc_context_verified = True
        self.product.save()
        self.product.refresh_from_db()
        self.assertTrue(self.product.ssvc_context_verified)

    def test_other_products_of_same_type_unaffected_by_each_others_overrides(self):
        other_product = Product.objects.create(
            name="SSVC Context Other Product", prod_type=self.prod_type, description="other",
        )
        self.prod_type.ssvc_exposure = ssvc_constants.EXPOSURE_LOCAL
        self.prod_type.save()
        self.product.ssvc_exposure = ssvc_constants.EXPOSURE_CONTROLLED
        self.product.save()
        other_product.refresh_from_db()

        self.assertEqual(self.product.effective_ssvc_exposure, ssvc_constants.EXPOSURE_CONTROLLED)
        self.assertEqual(other_product.effective_ssvc_exposure, ssvc_constants.EXPOSURE_LOCAL)
