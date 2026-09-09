# C++ / LibTorch Gate execution

The optional C++20 header uses the same last-axis selection as
`GateMask.apply()` and `schemen_gate.torch.GateLayer`. LibTorch supplies the
ATen CPU/CUDA operator and autograd; a C++ application needs no Python
interpreter or custom CUDA kernel.

```cpp
#include <schemen_gate/torch_gate.h>

// Boolean mask selected by the application's verified authority.
schemen_gate::TorchGate gate(trusted_mask);
auto gated = gate.apply(hidden);  // [..., width], same CPU/CUDA device
```

The constructor clones the mask, `mask()` returns a clone, and `to(device)`
returns a gate on the requested device. The caller authenticates grants and
owns mask resolution, placement, and bypass closure. A boolean mask is not a
credential. This header does not port Python PKI verification to C++.

## Build and test

Install CMake, a C++20 compiler, and LibTorch 2.13+ (or the repository's PyTorch
extra). From an installed, clean source checkout:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[torch]' pytest cmake
python scripts/check_native.py
```

For standalone LibTorch, without Python:

```bash
cmake -S native -B build/native -DCMAKE_PREFIX_PATH=/path/to/libtorch -DBUILD_TESTING=ON
cmake --build build/native --parallel 2
ctest --test-dir build/native --output-on-failure --no-tests=error
```

A parent CMake project can add this directory with `add_subdirectory()` and
link `schemen_gate_torch`. Build against the exact LibTorch ABI used by the
consumer. Gate's source identity alone does not identify the linked Torch
binaries. This directory is distributed in Git and excluded from the Python
wheel and sdist, which remain platform-independent Python distributions.

## CUDA acceptance

Use a CUDA-enabled PyTorch/LibTorch build, compatible toolkit/driver, and an
NVIDIA device. The device operator is supplied by LibTorch:

```bash
python scripts/check_native.py --require-cuda
python examples/torch_gate.py --device cuda
```

`--require-cuda` refuses to pass without CUDA hardware. It enables the C++ CUDA
test and runs Python GPU parity, gradient, stride, device-denial, and non-default
stream tests. CPU results are not CUDA execution evidence. Multi-GPU, CUDA graph
capture, vmap, speedups, hostile-host isolation, and model-level confinement
remain outside this first integration. See the
[execution contract](../docs/PYTORCH_AND_CPP.md) for arithmetic and authority limits.
