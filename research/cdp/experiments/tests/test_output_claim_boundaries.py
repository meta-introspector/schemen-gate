"""Finite controls for the interpretation of mathematical output claims."""

from fractions import Fraction
from itertools import combinations
from math import comb

import numpy as np

from schemen_gate import GateMask


def test_successful_guess_need_not_exhaust_the_space() -> None:
    supports = tuple(combinations(range(4), 2))
    assert len(supports) == 6
    for budget in range(1, len(supports) + 1):
        guesses = set(supports[:budget])
        successes = sum(secret in guesses for secret in supports)
        assert Fraction(successes, len(supports)) == Fraction(budget, 6)
    # One fixed guess succeeds for one possible secret. This challenges the
    # ordinary-success interpretation, not the consistency of opaque Recovers.
    assert sum(secret == supports[0] for secret in supports) == 1
    assert comb(768, 384) >= 2**384 > 2**256  # cardinality remains true


def test_valid_softmax_can_have_uniform_confidence() -> None:
    logits = np.zeros(2)
    weights = np.exp(logits - logits.max())
    probabilities = weights / weights.sum()
    np.testing.assert_array_equal(probabilities, [0.5, 0.5])


def test_bias_only_output_can_be_correct_under_both_regimes() -> None:
    projection = np.zeros((4, 2))
    bias = np.array([3.0, 0.0])
    for regime in range(2):
        mask = GateMask.derive(bytes(32), regime, 4, 2)
        logits = mask.apply(np.arange(4.0)) @ projection + bias
        weights = np.exp(logits - logits.max())
        probabilities = weights / weights.sum()
        assert np.all(probabilities > 0)
        assert np.isclose(probabilities.sum(), 1)
        assert probabilities.argmax() == 0  # stipulated correct class


def test_inactive_changes_preserve_logits_with_active_positive_control() -> None:
    mask = GateMask.derive(bytes(32), 0, 4, 2)
    active = mask.mask.astype(bool)
    hidden = np.arange(4.0)
    projection = np.arange(1.0, 9.0).reshape(4, 2)
    bias = np.array([1.0, -1.0])
    baseline = mask.apply(hidden) @ projection + bias

    changed = hidden.copy()
    changed[~active] = [-1000.0, 2000.0]
    np.testing.assert_array_equal(mask.apply(changed) @ projection + bias, baseline)

    changed[np.flatnonzero(active)[0]] += 1.0
    assert not np.array_equal(mask.apply(changed) @ projection + bias, baseline)
