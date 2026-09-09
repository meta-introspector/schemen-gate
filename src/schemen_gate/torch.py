"""Optional PyTorch execution layer for an already-authorized GateMask.

Import this module explicitly; the NumPy-only package does not import torch.
The caller owns authority resolution and model placement, including all bypasses.
"""

from __future__ import annotations

import torch
from torch import Tensor, nn

from schemen_gate._mask import GateMask

_DTYPES = (torch.float16, torch.bfloat16, torch.float32, torch.float64)


def apply_mask(hidden: Tensor, mask: Tensor) -> Tensor:
    """Apply a boolean last-axis mask with ATen CPU/CUDA autograd semantics.

    This is multiplication, matching GateMask.apply on supported floating
    tensors. Exact excluded zeros require finite values (IEEE 0 * NaN is NaN).
    Mask bytes are configuration, not proof of authorization.
    """
    if hidden.layout != torch.strided or mask.layout != torch.strided:
        raise ValueError("Gate tensors must have strided layout")
    if hidden.dtype not in _DTYPES or mask.dtype != torch.bool:
        raise ValueError("Gate requires floating input and a boolean mask")
    if mask.ndim != 1 or mask.numel() == 0:
        raise ValueError("Gate mask must be non-empty and one-dimensional")
    if hidden.ndim == 0 or hidden.shape[-1] != mask.numel():
        raise ValueError("Gate input's final dimension must equal the mask width")
    if hidden.device != mask.device or hidden.device.type not in ("cpu", "cuda"):
        raise ValueError("Gate input and mask must share a CPU or CUDA device")
    return torch.mul(hidden, mask)


class GateLayer(nn.Module):
    """Reusable execution module constructed from a trusted, resolved mask.

    The copied boolean buffer follows .to(device) but is deliberately absent
    from state_dict: model checkpoints cannot select the authorization mask.
    Reconstruct it from trusted configuration when loading a model.
    """

    _gate_mask: Tensor

    def __init__(self, gate: GateMask) -> None:
        super().__init__()
        if not isinstance(gate, GateMask):
            raise TypeError("GateLayer requires a resolved GateMask")
        self.register_buffer("_gate_mask", gate.to_torch(dtype=torch.bool), persistent=False)

    @property
    def mask(self) -> Tensor:
        """Return a detached copy; edits do not change this layer's mask."""
        return self._gate_mask.detach().clone()

    def forward(self, hidden: Tensor) -> Tensor:
        return apply_mask(hidden, self._gate_mask)
