"""
Tabelaryczne testy silnika SSVC (dojo/ssvc/services.py) wobec drzewa
org_custom_v1 — transkrypcja tree_source.md (36 kombinacji exploitation x
automatable x technical_impact x exposure, każda x 3 poziomy istotności
systemu = 108 liści), plus walidacja macierzy "Istotność systemu dla
organizacji" = f(mission_impact, safety_impact).

Celowo niezależna transkrypcja z tree_source.md, nie odczyt z org_custom_v1.yaml
— ma wychwycić błąd transkrypcji we danych drzewa, nie tylko w kodzie
silnika.
"""
from unittest import TestCase

from dojo.ssvc.services import (
    SSVCTreeError,
    available_trees,
    derive_criticality,
    evaluate,
    load_tree,
)

TREE_ID = "org_custom_v1"

# (exploitation, automatable, technical_impact, exposure) -> (low, medium, high)
# 1:1 z tabelą "Drzewo postępowania" w tree_source.md.
DECISION_TABLE = [
    (("none", "no", "partial", "local"), ("defer", "defer", "defer")),
    (("none", "no", "partial", "controlled"), ("defer", "defer", "defer")),
    (("none", "no", "partial", "open"), ("scheduled", "scheduled", "scheduled")),
    (("none", "no", "total", "local"), ("defer", "defer", "defer")),
    (("none", "no", "total", "controlled"), ("defer", "defer", "scheduled")),
    (("none", "no", "total", "open"), ("scheduled", "scheduled", "out_of_cycle")),
    (("none", "yes", "partial", "local"), ("defer", "defer", "scheduled")),
    (("none", "yes", "partial", "controlled"), ("defer", "defer", "out_of_cycle")),
    (("none", "yes", "partial", "open"), ("scheduled", "scheduled", "out_of_cycle")),
    (("none", "yes", "total", "local"), ("defer", "defer", "scheduled")),
    (("none", "yes", "total", "controlled"), ("defer", "defer", "out_of_cycle")),
    (("none", "yes", "total", "open"), ("scheduled", "scheduled", "out_of_cycle")),
    (("poc", "no", "partial", "local"), ("defer", "defer", "defer")),
    (("poc", "no", "partial", "controlled"), ("defer", "defer", "scheduled")),
    (("poc", "no", "partial", "open"), ("scheduled", "scheduled", "out_of_cycle")),
    (("poc", "no", "total", "local"), ("defer", "defer", "scheduled")),
    (("poc", "no", "total", "controlled"), ("defer", "scheduled", "out_of_cycle")),
    (("poc", "no", "total", "open"), ("scheduled", "out_of_cycle", "immediate")),
    (("poc", "yes", "partial", "local"), ("defer", "defer", "scheduled")),
    (("poc", "yes", "partial", "controlled"), ("defer", "defer", "out_of_cycle")),
    (("poc", "yes", "partial", "open"), ("scheduled", "scheduled", "immediate")),
    (("poc", "yes", "total", "local"), ("defer", "defer", "scheduled")),
    (("poc", "yes", "total", "controlled"), ("defer", "scheduled", "out_of_cycle")),
    (("poc", "yes", "total", "open"), ("scheduled", "out_of_cycle", "immediate")),
    (("active", "no", "partial", "local"), ("scheduled", "scheduled", "scheduled")),
    (("active", "no", "partial", "controlled"), ("scheduled", "scheduled", "out_of_cycle")),
    (("active", "no", "partial", "open"), ("scheduled", "scheduled", "immediate")),
    (("active", "no", "total", "local"), ("scheduled", "scheduled", "out_of_cycle")),
    (("active", "no", "total", "controlled"), ("scheduled", "out_of_cycle", "immediate")),
    (("active", "no", "total", "open"), ("scheduled", "immediate", "immediate")),
    (("active", "yes", "partial", "local"), ("scheduled", "scheduled", "out_of_cycle")),
    (("active", "yes", "partial", "controlled"), ("out_of_cycle", "out_of_cycle", "immediate")),
    (("active", "yes", "partial", "open"), ("immediate", "immediate", "immediate")),
    (("active", "yes", "total", "local"), ("scheduled", "out_of_cycle", "out_of_cycle")),
    (("active", "yes", "total", "controlled"), ("out_of_cycle", "immediate", "immediate")),
    (("active", "yes", "total", "open"), ("immediate", "immediate", "immediate")),
]

# Reprezentatywna para (mission_impact, safety_impact) per poziom istotności —
# jedna z kilku możliwych; pełna macierz 3x3 jest sprawdzana osobno, w
# test_mission_criticality_matrix.
CRITICALITY_REPS = {
    "low": ("minimal", "none"),
    "medium": ("minimal", "significant"),
    "high": ("critical", "major"),
}

# Macierz "Istotność systemu dla organizacji" (tree_source.md, sekcja 8).
MISSION_CRITICALITY_MATRIX = {
    ("minimal", "none"): "low",
    ("minimal", "significant"): "medium",
    ("minimal", "major"): "high",
    ("supportive", "none"): "medium",
    ("supportive", "significant"): "high",
    ("supportive", "major"): "high",
    ("critical", "none"): "high",
    ("critical", "significant"): "high",
    ("critical", "major"): "high",
}


class TestSSVCEngine(TestCase):

    def setUp(self):
        self.tree = load_tree(TREE_ID)

    def test_available_trees_lists_org_custom(self):
        self.assertIn(TREE_ID, available_trees())

    def test_tree_has_36_rules(self):
        self.assertEqual(len(self.tree["decision_table"]), 36)

    def test_mission_criticality_matrix(self):
        for (mission_impact, safety_impact), expected in MISSION_CRITICALITY_MATRIX.items():
            with self.subTest(mission_impact=mission_impact, safety_impact=safety_impact):
                self.assertEqual(
                    derive_criticality(self.tree, mission_impact, safety_impact),
                    expected,
                )

    def test_decision_table_exhaustive(self):
        """Każda z 36 x 3 = 108 kombinacji z tree_source.md daje właściwy wynik."""
        checked = 0
        for (exploitation, automatable, technical_impact, exposure), expected_outcomes in DECISION_TABLE:
            for tier, expected_outcome in zip(("low", "medium", "high"), expected_outcomes, strict=True):
                mission_impact, safety_impact = CRITICALITY_REPS[tier]
                values = {
                    "exploitation": exploitation,
                    "automatable": automatable,
                    "technical_impact": technical_impact,
                    "exposure": exposure,
                    "mission_impact": mission_impact,
                    "safety_impact": safety_impact,
                }
                with self.subTest(**values):
                    result = evaluate(self.tree, values)
                    self.assertEqual(result["outcome"], expected_outcome)
                    self.assertEqual(result["criticality"], tier)
                    self.assertEqual(result["tree_id"], "org_custom")
                    self.assertEqual(result["tree_version"], "1")
                checked += 1
        self.assertEqual(checked, 108)

    def test_evaluate_rejects_invalid_value(self):
        with self.assertRaises(SSVCTreeError):
            evaluate(self.tree, {
                "exploitation": "bogus",
                "automatable": "yes",
                "technical_impact": "partial",
                "exposure": "controlled",
                "mission_impact": "minimal",
                "safety_impact": "none",
            })

    def test_evaluate_rejects_missing_value(self):
        with self.assertRaises(SSVCTreeError):
            evaluate(self.tree, {
                "exploitation": "active",
                "automatable": "yes",
                # technical_impact missing
                "exposure": "controlled",
                "mission_impact": "minimal",
                "safety_impact": "none",
            })

    def test_load_tree_unknown_id_raises(self):
        with self.assertRaises(SSVCTreeError):
            load_tree("does_not_exist")
