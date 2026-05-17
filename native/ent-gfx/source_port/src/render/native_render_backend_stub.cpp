
#include "native_render_backend.hpp"

#ifndef __APPLE__

namespace entgfx {

std::unique_ptr<NativeRenderBackend> createNativeRenderBackend() {
  return {};
}

bool captureNativeFrameToActiveFramebuffer() {
  return false;
}

void clearNativeFrame() {}

} // namespace entgfx

#endif
