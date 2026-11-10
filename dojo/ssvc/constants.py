"""Canonical SSVC asset-context value vocabularies (Exposure, Mission
Impact, Safety Impact) — the single source for the value codes shared
between the decision-tree data (dojo/ssvc/trees/*.yaml) and the Django
model fields that capture them per-asset (dojo/product/models.py,
dojo/product_type/models.py). One definition here, instead of duplicate
choices tuples in both model files, is what keeps the DB schema and the
active tree's decision_points from drifting apart silently.

No Django imports (same reasoning as dojo/ssvc/services.py): labels here
are plain Polish strings, not gettext-wrapped — the Django model layer
wraps them with its own translation function at the point of use.
"""

EXPOSURE_LOCAL = "local"
EXPOSURE_CONTROLLED = "controlled"
EXPOSURE_OPEN = "open"
EXPOSURE_CHOICES = (
    (EXPOSURE_LOCAL, "Lokalna"),
    (EXPOSURE_CONTROLLED, "Kontrolowana"),
    (EXPOSURE_OPEN, "Otwarta"),
)
# Konserwatywny domyślny: najszersza ekspozycja, zgodnie z CLAUDE.md §6.3
# ("Exposure=Open dla assetów bez danych").
EXPOSURE_DEFAULT = EXPOSURE_OPEN

MISSION_IMPACT_MINIMAL = "minimal"
MISSION_IMPACT_SUPPORTIVE = "supportive"
MISSION_IMPACT_CRITICAL = "critical"
MISSION_IMPACT_CHOICES = (
    (MISSION_IMPACT_MINIMAL, "Minimalny"),
    (MISSION_IMPACT_SUPPORTIVE, "Wspomagający"),
    (MISSION_IMPACT_CRITICAL, "Kluczowy"),
)
# Konserwatywny domyślny: ten sam zasad co Exposure — nieznany system
# traktujemy jako najważniejszy, dopóki ktoś tego nie zweryfikuje.
MISSION_IMPACT_DEFAULT = MISSION_IMPACT_CRITICAL

SAFETY_IMPACT_NONE = "none"
SAFETY_IMPACT_SIGNIFICANT = "significant"
SAFETY_IMPACT_MAJOR = "major"
SAFETY_IMPACT_CHOICES = (
    (SAFETY_IMPACT_NONE, "Brak"),
    (SAFETY_IMPACT_SIGNIFICANT, "Znaczący"),
    (SAFETY_IMPACT_MAJOR, "Istotny"),
)
SAFETY_IMPACT_DEFAULT = SAFETY_IMPACT_MAJOR
