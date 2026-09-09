"""Toy parity, then a larger FFN projection using trusted fixture masks."""

from __future__ import annotations

import argparse

import torch

from schemen_gate import GateMask
from schemen_gate.torch import GateLayer


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device", choices=("cpu", "cuda"), default="cpu")
    args = parser.parse_args()
    if args.device == "cuda" and not torch.cuda.is_available():
        raise SystemExit("CUDA requested but unavailable")
    for batch, width in ((1, 4), (8, 16)):
        gate = GateMask.from_indices(range(0, width, 2), n_dims=width)
        layer = GateLayer(gate).to(args.device)
        x = torch.arange(1, batch * width + 1, device=args.device, dtype=torch.float32)
        x = x.reshape(batch, width).requires_grad_()
        projection = torch.ones(width, 3, device=args.device, requires_grad=True)
        gated = layer(x)
        if not torch.equal(gated, gate.apply(x)):
            raise AssertionError("forward parity failed")
        (gated @ projection).sum().backward()
        inactive = ~layer.mask
        if x.grad is None or projection.grad is None:
            raise AssertionError("missing gradient")
        if torch.count_nonzero(x.grad[:, inactive]) or torch.count_nonzero(
            projection.grad[inactive]
        ):
            raise AssertionError("inactive gradient changed")
        if not torch.count_nonzero(projection.grad[~inactive]):
            raise AssertionError("active-gradient detector did not fire")
        print(f"PASS: {args.device} batch={batch} width={width}, forward and aligned gradients")


if __name__ == "__main__":
    main()
