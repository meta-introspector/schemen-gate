#pragma once

#include <ATen/ATen.h>
#include <c10/util/Exception.h>

namespace schemen_gate {

// Execution primitive only. The embedding application authenticates and
// authorizes the mask before constructing the gate and owns bypass closure.
inline void validate_mask(const at::Tensor& mask) {
  TORCH_CHECK(mask.defined() && mask.layout() == at::kStrided,
              "Gate mask must be a defined strided tensor");
  TORCH_CHECK(mask.scalar_type() == at::kBool && mask.dim() == 1 &&
                  mask.numel() > 0,
              "Gate mask must be non-empty, one-dimensional, and boolean");
  TORCH_CHECK(mask.device().is_cpu() || mask.device().is_cuda(),
              "Gate mask must be on CPU or CUDA");
}

inline at::Tensor apply_mask(const at::Tensor& hidden, const at::Tensor& mask) {
  validate_mask(mask);
  TORCH_CHECK(hidden.defined() && hidden.layout() == at::kStrided,
              "Gate input must be a defined strided tensor");
  const auto dtype = hidden.scalar_type();
  TORCH_CHECK(dtype == at::kHalf || dtype == at::kBFloat16 ||
                  dtype == at::kFloat || dtype == at::kDouble,
              "Gate input must be float16, bfloat16, float32, or float64");
  TORCH_CHECK(hidden.dim() > 0 && hidden.size(-1) == mask.numel(),
              "Gate input's final dimension must equal the mask width");
  TORCH_CHECK(hidden.device() == mask.device(),
              "Gate input and mask must share a CPU or CUDA device");
  // Use the native ATen operator for dispatch, current-stream handling, and
  // autograd. Selection prevents excluded NaN/Inf values and gradients surviving.
  return at::where(mask, hidden, at::zeros({}, hidden.options()));
}

class TorchGate final {
 public:
  explicit TorchGate(const at::Tensor& authorized_mask) {
    validate_mask(authorized_mask);
    mask_ = authorized_mask.detach().clone();
  }

  at::Tensor apply(const at::Tensor& hidden) const {
    return apply_mask(hidden, mask_);
  }

  at::Tensor mask() const { return mask_.clone(); }

  TorchGate to(const at::Device& device) const {
    return TorchGate(mask_.to(device));
  }

 private:
  at::Tensor mask_;
};

}  // namespace schemen_gate
