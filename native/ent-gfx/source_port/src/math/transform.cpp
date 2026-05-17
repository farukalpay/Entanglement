
#include "entgfx/math/transform.hpp"

namespace entgfx {

Mat4 Transform::matrix() const {
  return translation(position) * rotation_z(rotation.z) * rotation_y(rotation.y) *
         rotation_x(rotation.x) * entgfx::scale(scale);
}

} // namespace entgfx
