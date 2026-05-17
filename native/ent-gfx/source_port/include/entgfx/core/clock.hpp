
#pragma once

namespace entgfx {

class Clock {
public:
  Clock();

  double tick();
  [[nodiscard]] double now() const;

private:
  double previous_seconds_ = 0.0;
};

} // namespace entgfx
