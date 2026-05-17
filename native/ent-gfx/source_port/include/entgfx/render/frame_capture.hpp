
#pragma once

#include <filesystem>

namespace entgfx {

void writeFramebufferPpm(const std::filesystem::path &path, int width, int height);

} // namespace entgfx
