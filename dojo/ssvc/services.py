"""SSVC decision engine: (tree, decision point values) -> decision.

Deliberately framework-agnostic: no Django imports. Trees are data
(dojo/ssvc/trees/*.yaml); this module only resolves them. Persistence of
the result as an immutable SSVCDecision record, provenance capture, and
recalculation triggers are a separate concern (dojo/ssvc/models.py /
signals.py, not yet built) — evaluate() just answers one question:
given this tree version and these inputs, what's the outcome.
"""

from __future__ import annotations

import functools
from pathlib import Path
from typing import Any

import yaml

TREES_DIR = Path(__file__).resolve().parent / "trees"

RULE_AXES = ("exploitation", "automatable", "technical_impact", "exposure")
REQUIRED_INPUTS = (*RULE_AXES, "mission_impact", "safety_impact")


class SSVCTreeError(Exception):
    """Raised when a tree definition is malformed, or evaluate() inputs don't match it."""


@functools.lru_cache(maxsize=None)
def load_tree(tree_id: str) -> dict[str, Any]:
    """Load and cache a tree definition by id (its filename, without .yaml)."""
    path = TREES_DIR / f"{tree_id}.yaml"
    if not path.is_file():
        raise SSVCTreeError(f"Unknown SSVC tree id: {tree_id!r} (looked for {path})")
    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f)


def available_trees() -> list[str]:
    return sorted(p.stem for p in TREES_DIR.glob("*.yaml"))


def _check_value(tree: dict[str, Any], point_id: str, value: str) -> None:
    point = tree["decision_points"].get(point_id)
    if point is None:
        raise SSVCTreeError(f"Tree {tree['id']!r} has no decision point {point_id!r}")
    if value not in point["values"]:
        raise SSVCTreeError(
            f"Invalid value {value!r} for decision point {point_id!r} in tree {tree['id']!r}; "
            f"expected one of {point['values']}",
        )


def derive_criticality(tree: dict[str, Any], mission_impact: str, safety_impact: str) -> str:
    """"Istotność systemu dla organizacji" = f(mission_impact, safety_impact), per the tree's matrix."""
    _check_value(tree, "mission_impact", mission_impact)
    _check_value(tree, "safety_impact", safety_impact)
    return tree["mission_criticality_matrix"][mission_impact][safety_impact]


def evaluate(tree: dict[str, Any], values: dict[str, str]) -> dict[str, Any]:
    """
    Evaluate one SSVC decision against `tree`.

    `values` must provide all of REQUIRED_INPUTS, using the English value
    codes declared under the tree's `decision_points` (e.g.
    exploitation="active", not "Aktywna" — labels are for display only).

    Returns a plain dict (tree_id, tree_version, criticality, outcome,
    inputs) — not an ORM object. Raises SSVCTreeError on missing/invalid
    inputs or (should the table ever be incomplete) an unmatched rule.
    """
    missing = [k for k in REQUIRED_INPUTS if k not in values]
    if missing:
        raise SSVCTreeError(f"Missing decision point value(s): {missing}")

    for point_id in RULE_AXES:
        _check_value(tree, point_id, values[point_id])

    criticality = derive_criticality(tree, values["mission_impact"], values["safety_impact"])

    for rule in tree["decision_table"]:
        when = rule["when"]
        if all(when[point_id] == values[point_id] for point_id in RULE_AXES):
            return {
                "tree_id": tree["id"],
                "tree_version": tree["version"],
                "criticality": criticality,
                "outcome": rule["outcomes"][criticality],
                "inputs": dict(values),
            }

    raise SSVCTreeError(
        f"No matching rule in tree {tree['id']!r} for "
        f"exploitation={values['exploitation']!r}, automatable={values['automatable']!r}, "
        f"technical_impact={values['technical_impact']!r}, exposure={values['exposure']!r}",
    )
