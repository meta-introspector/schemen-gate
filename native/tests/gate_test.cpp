#include <schemen_gate/torch_gate.h>
#include <torch/torch.h>

#include <iostream>
#include <stdexcept>
#include <string>

void require(bool condition, const char* message) {
  if (!condition) throw std::runtime_error(message);
}

template <typename Function>
void rejects(Function function) {
  bool rejected = false;
  try {
    function();
  } catch (const c10::Error&) {
    rejected = true;
  }
  require(rejected, "invalid input was accepted");
}

int main(int argc, char** argv) {
  try {
    const std::string target = argc == 2 ? argv[1] : "cpu";
    require(target == "cpu" || target == "cuda", "expected cpu or cuda");
    if (target == "cuda") {
      require(torch::cuda::is_available(), "CUDA required but unavailable");
    }
    const at::Device device(target);
    auto source = at::tensor({1, 0, 1, 0}, at::kLong).to(at::kBool).to(device);
    schemen_gate::TorchGate gate(source);
    source.fill_(false);
    gate.mask().fill_(false);
    for (const auto dtype : {at::kHalf, at::kBFloat16, at::kFloat, at::kDouble}) {
      auto options = at::TensorOptions().dtype(dtype).device(device);
      auto x = at::arange(1, 25, options).reshape({2, 3, 4});
      x.set_requires_grad(true);
      auto y = gate.apply(x);
      auto expected_mask = at::tensor({1, 0, 1, 0}, at::kLong).to(options);
      require(at::equal(y, x.detach() * expected_mask), "forward mismatch");
      y.sum().backward();
      require(at::equal(x.grad(), expected_mask.expand_as(x)), "gradient mismatch");
      auto strided = x.detach().transpose(0, 1);
      require(at::equal(gate.apply(strided), strided * expected_mask),
              "noncontiguous mismatch");
      require(gate.apply(at::empty({0, 4}, options)).numel() == 0,
              "empty batch mismatch");
    }
    rejects([&] { gate.apply(at::ones({2, 3}, source.options().dtype(at::kFloat))); });
    rejects([&] { gate.apply(at::ones({2, 4}, source.options().dtype(at::kLong))); });
    rejects([&] { gate.apply(at::ones({}, source.options().dtype(at::kFloat))); });
    rejects([&] { schemen_gate::TorchGate invalid(at::ones({4})); });
    rejects([&] { schemen_gate::TorchGate invalid(at::empty({0}, at::kBool)); });
    rejects([&] { schemen_gate::TorchGate invalid(at::ones({2, 4}, at::kBool)); });
    if (target == "cuda") {
      rejects([&] { gate.apply(at::ones({4})); });
    }
    std::cout << "PASS: " << target << " forward/backward, dtypes, strides, "
              << "copy isolation, empty batches, and rejection controls\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
