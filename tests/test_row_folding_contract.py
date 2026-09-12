"""Boundary and malformed-input tests for the generic row codec."""

from __future__ import annotations

import numpy as np
import pytest

import schemen_gate
import schemen_gate._regime0_fold as legacy_row_folding
from schemen_gate._row_folding import (
    FoldedRepresentation,
    fold_matrix,
    fold_vector,
    reconstruction_quality,
    unfold_matrix,
    unfold_vector,
)


def test_public_and_legacy_imports_resolve_to_generic_implementation() -> None:
    assert schemen_gate.fold_vector is fold_vector
    assert legacy_row_folding.fold_vector is fold_vector
    assert fold_vector.__module__ == "schemen_gate._row_folding"


@pytest.mark.parametrize("n_regimes", [0, -1, True])
def test_fold_rejects_invalid_regime_count(n_regimes: int) -> None:
    with pytest.raises(ValueError, match="positive integer"):
        fold_vector(np.ones(4), n_regimes)


def test_fold_vector_rejects_non_vector_input() -> None:
    with pytest.raises(ValueError, match="one-dimensional"):
        fold_vector(np.ones((2, 2)), 2)


def test_fold_matrix_rejects_higher_rank_input() -> None:
    with pytest.raises(ValueError, match="one- or two-dimensional"):
        fold_matrix(np.ones((1, 2, 2)), 2)


def test_representation_rejects_metadata_shape_mismatch() -> None:
    with pytest.raises(ValueError, match=r"rows must have shape \(2, 2\)"):
        FoldedRepresentation(
            rows=np.ones((1, 4)),
            n_dims=4,
            n_regimes=2,
            source_regime_id=0,
        )


def test_representation_detaches_caller_rows() -> None:
    rows = np.arange(4, dtype=np.float64).reshape(2, 2)
    folded = FoldedRepresentation(rows=rows, n_dims=4, n_regimes=2, source_regime_id=0)
    rows[0, 0] = 99.0
    np.testing.assert_array_equal(unfold_vector(folded), np.arange(4, dtype=np.float64))


def test_unfold_detects_rows_mutated_after_validation() -> None:
    folded = fold_vector(np.arange(4), 2)
    folded.rows = np.ones((1, 4))
    with pytest.raises(ValueError, match=r"rows must have shape \(2, 2\)"):
        unfold_vector(folded)


def test_unfold_matrix_rejects_empty_or_inconsistent_input() -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        unfold_matrix([])

    with pytest.raises(ValueError, match="same n_dims"):
        unfold_matrix([fold_vector(np.ones(4), 2), fold_vector(np.ones(6), 2)])


def test_quality_rejects_shape_mismatch() -> None:
    with pytest.raises(ValueError, match="same shape"):
        reconstruction_quality(np.ones(4), np.ones(8))
