# PyTorch, C++, and CUDA execution primitive

`GateMask.apply()` already accepts PyTorch tensors. `GateLayer` adds a reusable
`torch.nn.Module` whose copied mask follows `.to(device)`; the C++ header offers
the corresponding LibTorch API. Both use ATen selection and its existing
CPU/CUDA autograd implementation.

```python
import torch
from schemen_gate import GateMask
from schemen_gate.torch import GateLayer

# Local fixture: production supplies the mask resolved from verified scope.
mask = GateMask.from_indices([0, 2], n_dims=4)
gate = GateLayer(mask)
hidden = torch.tensor([[1., 2., 3., 4.]], requires_grad=True)
gated = gate(hidden)  # [[1., 0., 3., 0.]]
gated.sum().backward()  # hidden.grad == [[1., 0., 1., 0.]]
```

For CUDA, move both module and input to the same CUDA device. Unavailable or
mismatched devices are errors, with no CPU fallback. Run
`python examples/torch_gate.py` for a tiny control followed by a larger FFN
projection with active-gradient and excluded-gradient checks.

## Execution contract

- Strided float16, bfloat16, float32, or float64 input, shape `[..., width]`,
  with one boolean `[width]` mask shared across all leading rows.
- Output dtype/device match the input; input is not mutated. Noncontiguous
  inputs and empty leading dimensions are supported. Scalar, wrong-width,
  wrong-device, and unsupported dtype/layout inputs are rejected.
- `apply_mask(hidden, boolean_mask)` accepts trusted mask data. `GateLayer`
  instead snapshots a `GateMask`. Its `.mask` property returns a detached copy.
- The module mask is a nonpersistent buffer, absent from `state_dict()`.
  Reconstruct it from trusted authority when loading a model; checkpoints must
  not select their own permissions. Live process memory remains trusted.
- Excluded coordinates are positive zero, including when the input or incoming
  gradient is NaN, positive/negative infinity, or negative zero. Active values
  retain their original values and signs, including NaN/Inf. Boolean selection
  enforces this boundary without multiplying excluded values by zero.
- This guarantees the local gate output and gradient with respect to its input;
  upstream nonfinite derivatives may still produce NaNs elsewhere in a graph.
- Autograd and higher-order gradients use standard Torch operations.
  `torch.compile` is tested with `aot_eager` and `fullgraph=True`; other
  compilers require acceptance. This layer introduces no custom kernel or
  claimed speedup.

The primitive applies an already-authorized mask. It does not authenticate
callers, redeem one-use grants, install model hooks, or constrain weight decay,
momentum, optimizer state, caches, and alternate paths. Follow the
[training boundary](TRAINING.md) and
[certificate-to-Gate example](../examples/ai_pki_quickstart.py) for the distinct
authority and training contracts. The existing PKI and replay code is unchanged.

## Native build and acceptance

See [native build instructions](../native/README.md).
`python scripts/check_native.py` verifies C++ CPU behavior and the Python test
matrix. `--require-cuda` requires hardware and cannot silently pass with GPU
tests skipped. This design follows PyTorch's guidance to compose existing
operators when they express the operation:
[PyTorch operator guidance](https://docs.pytorch.org/tutorials/advanced/python_custom_ops.html).
