from django.db import models
from django.utils.translation import gettext as _


class SSVCDecision(models.Model):

    """
    Niemutowalny rekord historii decyzji SSVC dla jednego Finding (CLAUDE.md §6.1).

    Jedna ewaluacja silnika (dojo.ssvc.services.evaluate_finding) = jeden
    nowy wiersz — zmiana drzewa, atrybutów assetu albo danych wzbogacenia
    nie nadpisuje poprzedniej decyzji, tylko generuje nową (zob.
    dojo.ssvc.services.compute_and_record, które zapisuje nowy wiersz
    tylko gdy wynik lub wejścia faktycznie się zmieniły — §6.5).

    Rejestrowana tu historia JEST mechanizmem audytu dla samych decyzji
    (każdy wiersz to zdarzenie w czasie) — nie potrzebuje dodatkowo
    pghistory.track() jak Product/Finding, bo nic się tu nie nadpisuje.
    """

    finding = models.ForeignKey(
        "dojo.Finding", on_delete=models.CASCADE, related_name="ssvc_decisions",
    )

    tree_id = models.CharField(
        max_length=100, help_text=_("Identyfikator drzewa decyzyjnego użytego do tej decyzji."))
    tree_version = models.CharField(
        max_length=20, help_text=_("Wersja drzewa — zmiana drzewa nie przepisuje historii."))

    exploitation = models.CharField(max_length=10)
    automatable = models.CharField(max_length=10)
    technical_impact = models.CharField(max_length=10)
    exposure = models.CharField(max_length=10)
    mission_impact = models.CharField(max_length=10)
    safety_impact = models.CharField(max_length=11)

    criticality = models.CharField(
        max_length=10,
        help_text=_("Istotność systemu dla organizacji, wyliczona z mission_impact x safety_impact."))
    outcome = models.CharField(max_length=15, help_text=_("Wynik: defer/scheduled/out_of_cycle/immediate."))

    # Proweniencja KAŻDEGO punktu decyzyjnego (CLAUDE.md §6.1), np.:
    # {"exploitation": {"source": "auto:known_exploited"}, "automatable":
    #  {"source": "auto:cvss3_vector"}, "exposure": {"source": "product",
    #  "detail": "Product.ssvc_exposure"}, ...}
    # JSONField, nie 6 kolumn tekstowych — żeby dodanie nowego źródła albo
    # pola "detail" nie wymagało migracji.
    provenance = models.JSONField(default=dict, blank=True)

    # True, gdy KTÓRYKOLWIEK punkt decyzyjny nie mógł zostać wyznaczony
    # z realnych danych i dostał konserwatywną wartość domyślną — "nigdy
    # ciche pominięcie" (§6.4). Osobno od Product.ssvc_context_verified
    # (ten dotyczy kontekstu assetu, nie tej konkretnej decyzji findingu).
    needs_review = models.BooleanField(
        default=False,
        help_text=_("Któryś punkt decyzyjny nie miał wystarczających danych i dostał wartość konserwatywną."),
    )

    created = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("-created",)
        indexes = [
            models.Index(fields=["finding", "-created"], name="ssvc_decision_finding_created"),
        ]

    def __str__(self):
        return f"SSVCDecision(finding={self.finding_id}, outcome={self.outcome}, created={self.created})"

    def save(self, *args, **kwargs):
        if self.pk is not None:
            msg = "SSVCDecision is immutable: it cannot be updated, only created. Insert a new row instead."
            raise ValueError(msg)
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        msg = "SSVCDecision is immutable history: records are not meant to be deleted."
        raise ValueError(msg)
