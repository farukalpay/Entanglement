
#pragma once

#include "entgfx/math/mat4.hpp"
#include "entgfx/math/vec.hpp"

namespace entgfx {

struct Transform {
  Vec3 position{0.0f, 0.0f, 0.0f};
  Vec3 rotation{0.0f, 0.0f, 0.0f};
  Vec3 scale{1.0f, 1.0f, 1.0f};

  [[nodiscard]] Mat4 matrix() const;
};

inline Vec3 transformPoint(const Transform &transform, const Vec3 point) {
  return entgfx::transformPoint(transform.matrix(), point);
}

inline Vec3 transformVector(const Transform &transform, const Vec3 value) {
  return entgfx::transformVector(transform.matrix(), value);
}

} // namespace entgfx
