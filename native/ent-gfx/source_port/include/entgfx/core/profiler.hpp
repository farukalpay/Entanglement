
#pragma once

#include <chrono>

#ifndef ENTGFX_HAS_PROFILING_RUNTIME
#define ENTGFX_HAS_PROFILING_RUNTIME 0
#endif

namespace entgfx::profile {

bool startCapture();
bool stopCapture();
bool saveCapture(const char *path);
void shutdown();
void record(const char *name, double seconds);

class Scope {
public:
  explicit Scope(const char *name) : name_(name), start_(std::chrono::steady_clock::now()) {}

  Scope(const Scope &) = delete;
  Scope &operator=(const Scope &) = delete;

  ~Scope() {
    const auto end = std::chrono::steady_clock::now();
    record(name_, std::chrono::duration<double>(end - start_).count());
  }

private:
  const char *name_ = "";
  std::chrono::steady_clock::time_point start_;
};

} // namespace entgfx::profile

#if ENTGFX_HAS_PROFILING_RUNTIME
#define ENTGFX_PROFILE_JOIN_INNER(A, B) A##B
#define ENTGFX_PROFILE_JOIN(A, B) ENTGFX_PROFILE_JOIN_INNER(A, B)
#define ENTGFX_PROFILE_FRAME(NAME) ::entgfx::profile::Scope ENTGFX_PROFILE_JOIN(_entgfx_frame_, __LINE__)(NAME)
#define ENTGFX_PROFILE_SCOPE(NAME) ::entgfx::profile::Scope ENTGFX_PROFILE_JOIN(_entgfx_scope_, __LINE__)(NAME)
#define ENTGFX_PROFILE_FUNCTION() ENTGFX_PROFILE_SCOPE(__func__)
#else
#define ENTGFX_PROFILE_FRAME(NAME) ((void)0)
#define ENTGFX_PROFILE_SCOPE(NAME) ((void)0)
#define ENTGFX_PROFILE_FUNCTION() ((void)0)
#endif
