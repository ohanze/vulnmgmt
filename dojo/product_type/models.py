from django.contrib.postgres.indexes import GinIndex
from django.contrib.postgres.search import SearchVector
from django.db import models
from django.urls import reverse
from django.utils.functional import cached_property
from django.utils.translation import gettext as _

from dojo.base_models.base import BaseManager, BaseModel
from dojo.query_hooks import HookedBaseManager
from dojo.ssvc import constants as ssvc_constants


class Product_Type(BaseModel):

    """
    Product types represent the top level model, these can be business unit divisions, different offices or locations, development teams, or any other logical way of distinguishing "types" of products.
    `
       Examples:
         * IAM Team
         * Internal / 3rd Party
         * Main company / Acquisition
         * San Francisco / New York offices
    """

    name = models.CharField(max_length=255, unique=True)
    description = models.CharField(max_length=4000, null=True, blank=True)
    critical_product = models.BooleanField(default=False)
    key_product = models.BooleanField(default=False)
    authorized_users = models.ManyToManyField("dojo.Dojo_User", related_name="authorized_product_types", blank=True)

    # Domyślne SSVC dla assetów (Product) tego typu, które nie ustawiły
    # własnych wartości — patrz Product.effective_ssvc_*. Puste (None) =
    # brak domyślnej organizacyjnej; Product i tak spadnie na konserwatywny
    # domyślny z dojo.ssvc.constants.
    ssvc_exposure = models.CharField(
        max_length=10, choices=[(v, _(label)) for v, label in ssvc_constants.EXPOSURE_CHOICES],
        null=True, blank=True,
        verbose_name=_("Domyślna ekspozycja sieciowa (SSVC)"),
        help_text=_("Domyślna wartość dla produktów tego typu, które nie ustawiły własnej ekspozycji."))
    ssvc_mission_impact = models.CharField(
        max_length=10, choices=[(v, _(label)) for v, label in ssvc_constants.MISSION_IMPACT_CHOICES],
        null=True, blank=True,
        verbose_name=_("Domyślny wpływ na misję (SSVC)"),
        help_text=_("Domyślna wartość dla produktów tego typu, które nie ustawiły własnego wpływu na misję."))
    ssvc_safety_impact = models.CharField(
        max_length=11, choices=[(v, _(label)) for v, label in ssvc_constants.SAFETY_IMPACT_CHOICES],
        null=True, blank=True,
        verbose_name=_("Domyślny wpływ na bezpieczeństwo (SSVC)"),
        help_text=_(
            "Domyślna wartość dla produktów tego typu, które nie ustawiły własnego wpływu na bezpieczeństwo."))

    # Read and written only by plugins; open source never sets them.
    archived_at = models.DateTimeField(null=True, blank=True, editable=False)
    archive_batch = models.UUIDField(null=True, blank=True, editable=False)

    # objects is declared first, so it is the default manager; see dojo.query_hooks.
    objects = HookedBaseManager()
    unfiltered = BaseManager()

    class Meta:
        ordering = ("name",)
        indexes = [
            models.Index(fields=["archive_batch"], condition=models.Q(archive_batch__isnull=False), name="dojo_prod_type_archive_batch"),
            # Global search (pro/search/): weighted tsvector FTS + trigram fuzzy match.
            GinIndex(
                SearchVector("name", weight="A", config="english")
                + SearchVector("description", weight="B", config="english"),
                name="dojo_product_type_fts_gin",
            ),
            GinIndex(fields=["name"], opclasses=["gin_trgm_ops"], name="dojo_product_type_name_trgm"),
        ]

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("product_type", args=[str(self.id)])

    def get_breadcrumbs(self):
        return [{"title": str(self),
               "url": reverse("edit_product_type", args=(self.id,))}]

    @cached_property
    def critical_present(self):
        from dojo.models import Finding  # noqa: PLC0415 -- lazy import, avoids circular dependency
        c_findings = Finding.objects.filter(
            test__engagement__product__prod_type=self, severity="Critical")
        if c_findings.count() > 0:
            return True
        return None

    @cached_property
    def high_present(self):
        from dojo.models import Finding  # noqa: PLC0415 -- lazy import, avoids circular dependency
        c_findings = Finding.objects.filter(
            test__engagement__product__prod_type=self, severity="High")
        if c_findings.count() > 0:
            return True
        return None

    @cached_property
    def calc_health(self):
        from dojo.models import Finding  # noqa: PLC0415 -- lazy import, avoids circular dependency
        h_findings = Finding.objects.filter(
            test__engagement__product__prod_type=self, severity="High")
        c_findings = Finding.objects.filter(
            test__engagement__product__prod_type=self, severity="Critical")
        health = 100
        if c_findings.count() > 0:
            health = 40
            health -= ((c_findings.count() - 1) * 5)
        if h_findings.count() > 0:
            if health == 100:
                health = 60
            health -= ((h_findings.count() - 1) * 2)
        if health < 5:
            return 5
        return health

    # only used by bulk risk acceptance api
    @property
    def unaccepted_open_findings(self):
        from dojo.models import Finding  # noqa: PLC0415 -- lazy import, avoids circular dependency
        return Finding.objects.filter(risk_accepted=False, active=True, duplicate=False, test__engagement__product__prod_type=self)
