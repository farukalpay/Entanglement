
#pragma once

#include "entgfx/geometry/terrain_mesh.hpp"
#include "entgfx/render/mesh.hpp"

#include <functional>

namespace entgfx {

using MeshSurfaceSampler = std::function<TerrainSurfaceSample(Vec2)>;

struct MeshDrapeSettings {
  float surface_offset = 0.025f;
  bool raise_only = true;
  bool preserve_vertical_offset = false;
  float reference_y = 0.0f;
};

[[nodiscard]] CpuMesh drapeMeshToSurface(CpuMesh mesh, const MeshSurfaceSampler &sampler,
                                         MeshDrapeSettings settings = {});

} // namespace entgfx
