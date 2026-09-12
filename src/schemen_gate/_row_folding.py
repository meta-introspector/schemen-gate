"""Validated lossless row folding for generic numeric vectors.

The codec splits a one-dimensional vector into equally sized rows and joins
those rows again. It has no model, lane, Regime, authority, masking, storage,
or scheduling semantics. In particular, folding is not a security boundary.
Callers must enforce authorization and storage policy separately.
"""

from __future__ import annotations

import operator
from collections.abc import Sequence
from dataclasses import dataclass

import numpy as np
from numpy.typing import ArrayLike, NDArray


def _positive_int(value: int, *, name: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be a positive integer")
    try:
        normalized = operator.index(value)
    except TypeError as exc:
        raise ValueError(f"{name} must be a positive integer") from exc
    if normalized <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return normalized


def _vector(value: ArrayLike, *, name: str) -> NDArray[np.float64]:
    array = np.asarray(value, dtype=np.float64)
    if array.ndim != 1:
        raise ValueError(f"{name} must be one-dimensional, got shape {array.shape}")
    if array.size == 0:
        raise ValueError(f"{name} must not be empty")
    return array


@dataclass
class FoldedRepresentation:
    """A vector represented as equal-width rows.

    ``source_regime_id`` is retained for compatibility with the 1.x public
    API. It is untrusted metadata and is never authorization evidence.
    """

    rows: NDArray[np.float64]
    """Shape ``(n_regimes, dims_per_regime)``."""

    n_dims: int
    """Original vector dimensionality."""

    n_regimes: int
    """Number of equally sized rows in the representation."""

    source_regime_id: int
    """Legacy storage label; metadata only, not authorization evidence."""

    def __post_init__(self) -> None:
        self.n_dims = _positive_int(self.n_dims, name="n_dims")
        self.n_regimes = _positive_int(self.n_regimes, name="n_regimes")
        if self.n_dims % self.n_regimes != 0:
            raise ValueError(
                f"n_dims ({self.n_dims}) must be divisible by n_regimes ({self.n_regimes})"
            )
        if isinstance(self.source_regime_id, bool):
            raise ValueError("source_regime_id must be a non-negative integer")
        try:
            self.source_regime_id = operator.index(self.source_regime_id)
        except TypeError as exc:
            raise ValueError("source_regime_id must be a non-negative integer") from exc
        if self.source_regime_id < 0:
            raise ValueError("source_regime_id must be a non-negative integer")

        rows = np.asarray(self.rows, dtype=np.float64)
        expected_shape = (self.n_regimes, self.dims_per_regime)
        if rows.shape != expected_shape:
            raise ValueError(f"rows must have shape {expected_shape}, got {rows.shape}")
        self.rows = rows.copy()

    @property
    def dims_per_regime(self) -> int:
        return self.n_dims // self.n_regimes

    @property
    def n_rows(self) -> int:
        return int(self.rows.shape[0])


def _validated_rows(folded: FoldedRepresentation) -> NDArray[np.float64]:
    if not isinstance(folded, FoldedRepresentation):
        raise TypeError("folded must be a FoldedRepresentation")
    rows = np.asarray(folded.rows, dtype=np.float64)
    expected_shape = (folded.n_regimes, folded.dims_per_regime)
    if rows.shape != expected_shape:
        raise ValueError(f"rows must have shape {expected_shape}, got {rows.shape}")
    return rows


def fold_vector(vector: ArrayLike, n_regimes: int) -> FoldedRepresentation:
    """Split a vector into ``n_regimes`` equal rows without information loss.

    This generic codec is not a security boundary: it does not resolve a
    Regime, apply a mask, authorize storage, or attest a model topology.
    """
    normalized_regimes = _positive_int(n_regimes, name="n_regimes")
    normalized_vector = _vector(vector, name="vector")
    n_dims = int(normalized_vector.shape[0])
    if n_dims % normalized_regimes != 0:
        raise ValueError(f"n_dims ({n_dims}) must be divisible by n_regimes ({normalized_regimes})")

    rows = normalized_vector.reshape(normalized_regimes, n_dims // normalized_regimes)
    return FoldedRepresentation(
        rows=rows,
        n_dims=n_dims,
        n_regimes=normalized_regimes,
        source_regime_id=0,
    )


def unfold_vector(folded: FoldedRepresentation) -> NDArray[np.float64]:
    """Join a validated folded representation into its original vector."""
    return _validated_rows(folded).reshape(folded.n_dims).copy()


def fold_matrix(matrix: ArrayLike, n_regimes: int) -> list[FoldedRepresentation]:
    """Fold a vector or each row of a two-dimensional matrix independently."""
    normalized = np.asarray(matrix, dtype=np.float64)
    if normalized.ndim == 1:
        return [fold_vector(normalized, n_regimes)]
    if normalized.ndim != 2:
        raise ValueError(f"matrix must be one- or two-dimensional, got shape {normalized.shape}")
    if normalized.shape[0] == 0:
        raise ValueError("matrix must contain at least one row")
    return [fold_vector(row, n_regimes) for row in normalized]


def unfold_matrix(folded_rows: Sequence[FoldedRepresentation]) -> NDArray[np.float64]:
    """Reconstruct a matrix from a non-empty, dimensionally consistent sequence."""
    if not folded_rows:
        raise ValueError("folded_rows must not be empty")
    n_dims = folded_rows[0].n_dims
    if any(folded.n_dims != n_dims for folded in folded_rows):
        raise ValueError("all folded rows must have the same n_dims")
    return np.stack([unfold_vector(folded) for folded in folded_rows])


def reconstruction_quality(
    original: ArrayLike,
    reconstructed: ArrayLike,
) -> dict[str, float]:
    """Measure cosine similarity, L2 distance, and relative reconstruction error."""
    normalized_original = _vector(original, name="original")
    normalized_reconstructed = _vector(reconstructed, name="reconstructed")
    if normalized_original.shape != normalized_reconstructed.shape:
        raise ValueError(
            "original and reconstructed must have the same shape, got "
            f"{normalized_original.shape} and {normalized_reconstructed.shape}"
        )

    norm_o = np.linalg.norm(normalized_original)
    norm_r = np.linalg.norm(normalized_reconstructed)
    if norm_o < 1e-12 or norm_r < 1e-12:
        return {
            "cosine_similarity": 0.0,
            "l2_distance": float("inf"),
            "relative_error": float("inf"),
        }

    cosine = float(np.dot(normalized_original, normalized_reconstructed) / (norm_o * norm_r))
    l2 = float(np.linalg.norm(normalized_original - normalized_reconstructed))
    relative = float(l2 / norm_o)
    return {
        "cosine_similarity": cosine,
        "l2_distance": l2,
        "relative_error": relative,
    }


__all__ = [
    "FoldedRepresentation",
    "fold_matrix",
    "fold_vector",
    "reconstruction_quality",
    "unfold_matrix",
    "unfold_vector",
]
