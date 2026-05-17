
#pragma once

#include "entgfx/math/vec.hpp"
#include "entgfx/render/mesh.hpp"

#include <vector>

namespace entgfx {

struct StrokePoint {
  Vec2 position{};
  float width = 0.035f;
};

struct StrokePath {
  std::vector<StrokePoint> points;
};

struct StrokeMeshSpec {
  std::vector<StrokePath> paths;
  float plane_z = 0.0f;
};

[[nodiscard]] CpuMesh makeStrokeRibbonMesh(const StrokeMeshSpec &spec);

} // namespace entgfx
