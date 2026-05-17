
#include "entgfx/render/frame_capture.hpp"

#include "entgfx/render/software_framebuffer.hpp"
#include "native_render_backend.hpp"

#include <stdexcept>

namespace entgfx {

void writeFramebufferPpm(const std::filesystem::path &path, const int width, const int height) {
  if (width <= 0 || height <= 0) {
    throw std::invalid_argument("Framebuffer capture requires a positive size.");
  }
  (void)captureNativeFrameToActiveFramebuffer();
  activeFrameBuffer().writePpm(path, width, height);
}

} // namespace entgfx
