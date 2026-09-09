"""Framework parity and rejection tests for the optional execution primitive."""

from __future__ import annotations

import pytest

torch = pytest.importorskip("torch")

from schemen_gate import GateMask  # noqa: E402
from schemen_gate.torch import GateLayer, apply_mask  # noqa: E402


@pytest.fixture(params=["cpu", "cuda"])
def device(request: pytest.FixtureRequest) -> str:
    if request.param == "cuda" and not torch.cuda.is_available():
        pytest.skip("CUDA hardware unavailable")
    return str(request.param)


@pytest.mark.parametrize("dtype", [torch.float16, torch.bfloat16, torch.float32, torch.float64])
def test_forward_and_backward_match_existing_gate(device: str, dtype: torch.dtype) -> None:
    gate = GateMask.from_indices([0, 2], n_dims=4, regime_id=1)
    layer = GateLayer(gate).to(device)
    x = torch.arange(1, 25, dtype=dtype, device=device).reshape(2, 3, 4).requires_grad_()
    reference = x.detach().clone().requires_grad_()
    y = layer(x)
    expected = gate.apply(reference)
    assert torch.equal(y, expected)
    y.square().sum().backward()
    expected.square().sum().backward()
    assert torch.equal(x.grad, reference.grad)
    assert torch.count_nonzero(x.grad[..., [1, 3]]) == 0
    assert torch.count_nonzero(x.grad[..., [0, 2]]) > 0
    assert y.data_ptr() != x.data_ptr()


def test_noncontiguous_input_mask_and_empty_batches(device: str) -> None:
    x = torch.arange(24.0, device=device).reshape(2, 4, 3).transpose(1, 2)
    mask = torch.tensor([True, False, False, False, True, False, False, False], device=device)[::2]
    assert not x.is_contiguous() and not mask.is_contiguous()
    assert torch.equal(apply_mask(x, mask), x * mask)
    assert apply_mask(torch.empty(2, 0, 4, device=device), mask).shape == (2, 0, 4)


def test_mask_copy_and_checkpoint_do_not_replace_authority() -> None:
    gate = GateMask.from_indices([0], n_dims=2)
    layer = GateLayer(gate)
    layer.mask.fill_(True)
    assert torch.equal(layer(torch.ones(2)), torch.tensor([1.0, 0.0]))
    assert torch.equal(gate.to_torch(), torch.tensor([1.0, 0.0]))
    assert layer.state_dict() == {}
    with pytest.raises(RuntimeError, match="Unexpected key"):
        layer.load_state_dict({"_gate_mask": torch.ones(2, dtype=torch.bool)})
    assert layer.to(dtype=torch.float64).mask.dtype == torch.bool


@pytest.mark.parametrize(
    ("hidden", "mask"),
    [
        (torch.ones(2), torch.ones(2)),
        (torch.ones(2), torch.ones(1, 2, dtype=torch.bool)),
        (torch.ones(2), torch.empty(0, dtype=torch.bool)),
        (torch.ones(3), torch.ones(2, dtype=torch.bool)),
        (torch.tensor(1.0), torch.ones(1, dtype=torch.bool)),
        (torch.ones(2, dtype=torch.int64), torch.ones(2, dtype=torch.bool)),
        (torch.ones(2, dtype=torch.complex64), torch.ones(2, dtype=torch.bool)),
        (torch.ones(2).to_sparse(), torch.ones(2, dtype=torch.bool)),
        (torch.ones(2), torch.ones(2, dtype=torch.bool).to_sparse()),
    ],
)
def test_malformed_inputs_are_rejected(hidden: torch.Tensor, mask: torch.Tensor) -> None:
    with pytest.raises(ValueError):
        apply_mask(hidden, mask)


def test_first_and_second_order_autograd() -> None:
    layer = GateLayer(GateMask.from_indices([0, 2], n_dims=4))
    x = torch.randn(2, 4, dtype=torch.float64, requires_grad=True)
    assert torch.autograd.gradcheck(layer, (x,))
    assert torch.autograd.gradgradcheck(layer, (x,))


def test_compiled_forward_and_backward() -> None:
    layer = GateLayer(GateMask.from_indices([0, 2], n_dims=4))
    compiled = torch.compile(layer, backend="aot_eager", fullgraph=True)
    x = torch.randn(3, 4, requires_grad=True)
    expected = layer(x)
    actual = compiled(x)
    assert torch.equal(actual, expected)
    assert torch.equal(
        torch.autograd.grad(actual.sum(), x)[0],
        torch.autograd.grad(expected.sum(), x)[0],
    )


def test_nonfinite_values_preserve_existing_multiplication_semantics() -> None:
    gate = GateMask.from_indices([0], n_dims=4)
    x = torch.tensor([float("inf"), float("nan"), float("inf"), -0.0])
    torch.testing.assert_close(GateLayer(gate)(x), gate.apply(x), rtol=0, atol=0, equal_nan=True)


@pytest.mark.skipif(not torch.cuda.is_available(), reason="CUDA hardware unavailable")
def test_cuda_device_mismatch_and_current_stream() -> None:
    layer = GateLayer(GateMask.from_indices([0, 2], n_dims=4)).cuda()
    with pytest.raises(ValueError, match="share"):
        layer(torch.ones(4))
    stream = torch.cuda.Stream()
    with torch.cuda.stream(stream):
        x = torch.arange(16.0, device="cuda").reshape(4, 4).requires_grad_()
        y = layer(x)
        y.sum().backward()
    stream.synchronize()
    assert torch.equal(y, x.detach() * layer.mask)
    assert torch.equal(x.grad, layer.mask.expand_as(x).to(x.dtype))
