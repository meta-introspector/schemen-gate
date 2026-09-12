"""Compatibility imports for the former Regime-0-named row codec.

The implementation is generic and lives in :mod:`schemen_gate._row_folding`.
This private import path remains available so existing 1.x consumers do not
break. Neither module implements a Gate, a Hydra lane, or authorization.
"""

from schemen_gate._row_folding import (
    FoldedRepresentation,
    fold_matrix,
    fold_vector,
    reconstruction_quality,
    unfold_matrix,
    unfold_vector,
)

__all__ = [
    "FoldedRepresentation",
    "fold_matrix",
    "fold_vector",
    "reconstruction_quality",
    "unfold_matrix",
    "unfold_vector",
]
