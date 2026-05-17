
#include "entgfx/render/render_device.hpp"

#include "entgfx/asset/mesh_pipeline.hpp"
#include "entgfx/core/profiler.hpp"
#include "entgfx/math/color.hpp"
#include "entgfx/render/software_framebuffer.hpp"
#include "entgfx/scene/scene.hpp"
#include "native_render_backend.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <limits>
#include <stdexcept>
#include <unordered_set>
#include <vector>

namespace {

constexpr int kSphereSegments = 48;
constexpr int kSphereRings = 24;
constexpr int kRockSegments = 28;
constexpr int kRockRings = 16;
constexpr int kCrystalSides = 6;
constexpr int kPillarSides = 10;
constexpr float kPlaneSize = 12.0f;
constexpr float kContactShadowPlaneSize = 2.0f;
constexpr float kTau = 6.28318530718f;

struct Vec4f {
  float x = 0.0f;
  float y = 0.0f;
  float z = 0.0f;
  float w = 1.0f;
};

struct LocalBounds {
  entgfx::Vec3 min{};
  entgfx::Vec3 max{};
};

struct ProjectedVertex {
  bool valid = false;
  entgfx::Vec3 world_position{};
  entgfx::Vec3 normal{};
  entgfx::Vec2 uv{};
  float ambient_occlusion = 1.0f;
  float x = 0.0f;
  float y = 0.0f;
  float depth = 1.0f;
};

float saturate(const float value) {
  return std::clamp(value, 0.0f, 1.0f);
}

float smoothstep(const float edge0, const float edge1, const float value) {
  const float range = std::max(edge1 - edge0, 0.0001f);
  const float t = saturate((value - edge0) / range);
  return t * t * (3.0f - 2.0f * t);
}

entgfx::Vec3 mixVec(const entgfx::Vec3 a, const entgfx::Vec3 b, const float t) {
  const float amount = saturate(t);
  return a * (1.0f - amount) + b * amount;
}

entgfx::MeshProcessOptions renderMeshOptions() {
  entgfx::MeshProcessOptions options;
  options.generate_tangents = false;
  return options;
}

Vec4f transformPoint4(const entgfx::Mat4 &matrix, const entgfx::Vec3 point) {
  return {
      matrix.m[0] * point.x + matrix.m[4] * point.y + matrix.m[8] * point.z + matrix.m[12],
      matrix.m[1] * point.x + matrix.m[5] * point.y + matrix.m[9] * point.z + matrix.m[13],
      matrix.m[2] * point.x + matrix.m[6] * point.y + matrix.m[10] * point.z + matrix.m[14],
      matrix.m[3] * point.x + matrix.m[7] * point.y + matrix.m[11] * point.z + matrix.m[15],
  };
}

float fractValue(const float value) {
  return value - std::floor(value);
}

float hash31(entgfx::Vec3 p) {
  p = {fractValue(p.x * 0.1031f), fractValue(p.y * 0.11369f), fractValue(p.z * 0.13787f)};
  const float d = p.x * (p.y + 19.19f) + p.y * (p.z + 19.19f) + p.z * (p.x + 19.19f);
  p = p + entgfx::Vec3{d, d, d};
  return fractValue((p.x + p.y) * p.z);
}

float valueNoise(const entgfx::Vec3 p) {
  const entgfx::Vec3 i{std::floor(p.x), std::floor(p.y), std::floor(p.z)};
  entgfx::Vec3 f{fractValue(p.x), fractValue(p.y), fractValue(p.z)};
  f = f * f * (entgfx::Vec3{3.0f, 3.0f, 3.0f} - f * 2.0f);

  const float n000 = hash31(i + entgfx::Vec3{0.0f, 0.0f, 0.0f});
  const float n100 = hash31(i + entgfx::Vec3{1.0f, 0.0f, 0.0f});
  const float n010 = hash31(i + entgfx::Vec3{0.0f, 1.0f, 0.0f});
  const float n110 = hash31(i + entgfx::Vec3{1.0f, 1.0f, 0.0f});
  const float n001 = hash31(i + entgfx::Vec3{0.0f, 0.0f, 1.0f});
  const float n101 = hash31(i + entgfx::Vec3{1.0f, 0.0f, 1.0f});
  const float n011 = hash31(i + entgfx::Vec3{0.0f, 1.0f, 1.0f});
  const float n111 = hash31(i + entgfx::Vec3{1.0f, 1.0f, 1.0f});

  const float nx00 = std::lerp(n000, n100, f.x);
  const float nx10 = std::lerp(n010, n110, f.x);
  const float nx01 = std::lerp(n001, n101, f.x);
  const float nx11 = std::lerp(n011, n111, f.x);
  const float nxy0 = std::lerp(nx00, nx10, f.y);
  const float nxy1 = std::lerp(nx01, nx11, f.y);
  return std::lerp(nxy0, nxy1, f.z);
}

bool isTerrainPattern(const entgfx::SurfacePattern pattern) {
  return pattern == entgfx::SurfacePattern::GrassSoil ||
         pattern == entgfx::SurfacePattern::TerrainBlend ||
         pattern == entgfx::SurfacePattern::LayeredTerrain;
}

float projectedNoise(const entgfx::Vec3 world_position, entgfx::Vec3 normal, const float scale,
                     const float salt) {
  normal = entgfx::normalize(normal);
  if (entgfx::length(normal) <= 0.0001f) {
    normal = {0.0f, 1.0f, 0.0f};
  }
  entgfx::Vec3 weights{std::pow(std::abs(normal.x), 4.0f), std::pow(std::abs(normal.y), 4.0f),
                      std::pow(std::abs(normal.z), 4.0f)};
  const float weight_sum = std::max(weights.x + weights.y + weights.z, 0.0001f);
  weights = weights / weight_sum;
  const float xy = valueNoise({world_position.x * scale, world_position.y * scale, salt});
  const float xz = valueNoise({world_position.x * scale, world_position.z * scale, salt + 11.7f});
  const float zy = valueNoise({world_position.z * scale, world_position.y * scale, salt + 23.4f});
  return xy * weights.z + xz * weights.y + zy * weights.x;
}

float terrainFbm(const entgfx::Vec3 world_position, const entgfx::Vec3 normal, const float scale,
                 const float salt) {
  float sum = 0.0f;
  float amplitude = 0.56f;
  float amplitude_sum = 0.0f;
  float frequency = scale;
  for (int octave = 0; octave < 4; ++octave) {
    sum += projectedNoise(world_position, normal, frequency,
                          salt + static_cast<float>(octave) * 17.0f) *
           amplitude;
    amplitude_sum += amplitude;
    frequency *= 2.08f;
    amplitude *= 0.52f;
  }
  return amplitude_sum > 0.0f ? sum / amplitude_sum : 0.0f;
}

entgfx::Vec3 terrainLayeredAlbedo(const entgfx::Material &material, const entgfx::Vec3 world_position,
                                 const entgfx::Vec3 normal) {
  const float pattern_id = static_cast<float>(static_cast<int>(material.surface_pattern));
  const float detail_scale = std::max(material.detail_scale, 0.001f);
  const float macro_scale = 0.018f + std::sqrt(detail_scale) * 0.011f;
  const float mid_scale = 0.055f + detail_scale * 0.018f;
  const float fine_scale = 0.38f + detail_scale * 0.055f;
  const float macro = terrainFbm(world_position, normal, macro_scale, pattern_id * 3.7f);
  const float mid = terrainFbm(world_position, normal, mid_scale, pattern_id * 5.1f + 9.0f);
  const float fine = terrainFbm(world_position, normal, fine_scale, pattern_id * 7.9f + 2.0f);
  const float ridge = 1.0f - std::abs(terrainFbm(world_position, normal, mid_scale * 1.85f,
                                                 pattern_id * 2.4f + 31.0f) *
                                          2.0f -
                                      1.0f);
  const float up = saturate(entgfx::normalize(normal).y);
  const float slope = 1.0f - smoothstep(0.54f, 0.92f, up);
  const float altitude = smoothstep(-0.20f, 2.80f, world_position.y + (macro - 0.5f) * 0.65f);
  const float soil_weight = saturate(slope * 0.46f + (0.54f - mid) * 0.46f + ridge * 0.10f);
  const float rock_weight =
      saturate(smoothstep(0.70f, 1.08f, slope + ridge * 0.14f + altitude * 0.04f)) * 0.52f;
  const float grass_weight =
      saturate(0.70f + (macro - 0.45f) * 0.28f + (fine - 0.50f) * 0.12f - soil_weight * 0.36f -
               rock_weight * 0.58f + material.pattern_depth * 1.10f);

  const entgfx::Vec3 base = material.base_color;
  const entgfx::Vec3 grass =
      mixVec(base * entgfx::Vec3{0.78f, 1.04f, 0.58f}, {0.18f, 0.28f, 0.12f}, 0.24f);
  const entgfx::Vec3 dry_grass =
      mixVec(base * entgfx::Vec3{0.98f, 0.90f, 0.62f}, {0.34f, 0.30f, 0.18f}, 0.26f);
  const entgfx::Vec3 soil =
      mixVec(base * entgfx::Vec3{1.02f, 0.76f, 0.52f}, {0.30f, 0.23f, 0.16f}, 0.30f);
  const entgfx::Vec3 rock =
      mixVec(base * entgfx::Vec3{0.94f, 0.94f, 0.86f}, {0.44f, 0.42f, 0.36f}, 0.32f);
  entgfx::Vec3 albedo = mixVec(soil, dry_grass, saturate(grass_weight * 0.30f + macro * 0.18f));
  albedo = mixVec(albedo, grass, grass_weight);
  albedo = mixVec(albedo, rock, rock_weight);

  const float fiber = projectedNoise(world_position + entgfx::Vec3{fine * 1.7f, 0.0f, macro}, normal,
                                     fine_scale * 2.35f, pattern_id + 43.0f);
  const float pebble =
      projectedNoise(world_position, normal, fine_scale * 3.8f, pattern_id + 67.0f);
  albedo = albedo * (0.92f + fine * 0.10f + fiber * grass_weight * 0.05f);
  albedo = mixVec(albedo, albedo * 0.82f, saturate(pebble * soil_weight * 0.08f + slope * 0.05f));
  return entgfx::clamp(albedo, 0.0f, 4.0f);
}

entgfx::Vec3 patternSamplePosition(const entgfx::Material &material, const entgfx::Vec3 world_position,
                                  const entgfx::Vec3 normal, const double frame_seconds) {
  const float pattern_id = static_cast<float>(static_cast<int>(material.surface_pattern));
  const float scale = std::max(material.detail_scale, 0.001f);
  return world_position * scale + normal * 0.73f +
         entgfx::Vec3{pattern_id * 0.17f, pattern_id * 0.31f,
                     static_cast<float>(frame_seconds) * 0.015f};
}

float projectedFbm(const entgfx::Material &material, const entgfx::Vec3 world_position,
                   const entgfx::Vec3 normal, const float multiplier, const float salt) {
  const float scale = std::max(material.detail_scale, 0.001f) * multiplier;
  return terrainFbm(world_position, normal, scale, salt);
}

float ridge(const float value) {
  return 1.0f - std::abs(value * 2.0f - 1.0f);
}

entgfx::Vec3 structuredStoneAlbedo(const entgfx::Material &material, const entgfx::Vec3 world_position,
                                  const entgfx::Vec3 normal) {
  const float mortar = std::max(material.pattern_mortar, 0.005f);
  const entgfx::Vec2 structural_uv = std::abs(normal.y) > 0.55f
                                        ? entgfx::Vec2{world_position.x, world_position.z}
                                        : entgfx::Vec2{world_position.x, world_position.y};
  const entgfx::Vec2 scaled{structural_uv.x * std::max(material.pattern_scale.x, 0.001f),
                           structural_uv.y * std::max(material.pattern_scale.y, 0.001f)};
  const entgfx::Vec2 cell{fractValue(scaled.x), fractValue(scaled.y)};
  const float edge = std::min(std::min(cell.x, 1.0f - cell.x), std::min(cell.y, 1.0f - cell.y));
  const float line = 1.0f - smoothstep(mortar, mortar + 0.035f, edge);
  const float broad = projectedFbm(material, world_position, normal, 0.11f, 19.0f);
  const float fine = projectedFbm(material, world_position, normal, 0.84f, 29.0f);
  entgfx::Vec3 block = material.base_color * (0.82f + broad * 0.22f + fine * 0.12f);
  block = mixVec(block, block * entgfx::Vec3{1.10f, 1.04f, 0.92f}, material.edge_wear * ridge(fine));
  return mixVec(block, material.base_color * 0.36f, line * 0.70f);
}

entgfx::Vec3 caveRockAlbedo(const entgfx::Material &material, const entgfx::Vec3 world_position,
                           const entgfx::Vec3 normal) {
  const float strata =
      0.5f + 0.5f * std::sin((world_position.y * material.pattern_scale.y +
                              world_position.z * 0.33f + world_position.x * 0.18f) *
                             1.75f);
  const float broad = projectedFbm(material, world_position, normal, 0.10f, 41.0f);
  const float fine = projectedFbm(material, world_position, normal, 0.88f, 53.0f);
  const float crack = ridge(projectedFbm(material, world_position, normal, 0.42f, 67.0f));
  entgfx::Vec3 damp = material.base_color * entgfx::Vec3{0.72f, 0.70f, 0.62f};
  entgfx::Vec3 mineral = material.base_color * entgfx::Vec3{1.24f, 1.13f, 0.92f};
  entgfx::Vec3 albedo = mixVec(damp, material.base_color, broad * 0.74f);
  albedo =
      mixVec(albedo, mineral,
             saturate(strata * 0.18f + ridge(fine) * 0.12f) * saturate(material.pattern_contrast));
  albedo = mixVec(albedo, albedo * 0.50f,
                  smoothstep(0.68f, 0.96f, crack) * (0.35f + material.pattern_depth * 1.8f));
  return entgfx::clamp(albedo * (0.82f + fine * 0.22f), 0.0f, 4.0f);
}

entgfx::Vec3 coalVeinAlbedo(const entgfx::Material &material, const entgfx::Vec3 world_position,
                           const entgfx::Vec3 normal) {
  const float vein_a = ridge(projectedFbm(material, world_position, normal, 0.32f, 71.0f));
  const float vein_b =
      ridge(projectedFbm(material, world_position + normal * 0.17f, normal, 0.76f, 89.0f));
  const float vein = smoothstep(0.72f, 0.96f, vein_a * vein_b + material.pattern_depth * 0.52f);
  const float sheen =
      smoothstep(0.50f, 0.95f, projectedFbm(material, world_position, normal, 1.55f, 97.0f));
  entgfx::Vec3 coal = material.base_color * (0.54f + sheen * 0.32f);
  const entgfx::Vec3 warm_vein =
      mixVec({0.22f, 0.15f, 0.075f}, material.emission_color + material.base_color, 0.35f);
  return mixVec(coal, warm_vein, vein * 0.78f);
}

entgfx::Vec3 organicFiberAlbedo(const entgfx::Material &material, const entgfx::Vec3 world_position,
                               const entgfx::Vec3 normal, const entgfx::Vec2 uv, const float salt) {
  const float flow =
      world_position.y * material.pattern_scale.y +
      (world_position.x + world_position.z * 0.38f) * material.pattern_scale.x * 0.18f;
  const float noise = projectedFbm(material, world_position, normal, 0.70f, salt);
  const float strand = 0.5f + 0.5f * std::sin(flow * 0.46f + noise * 5.3f + uv.x * kTau);
  const float strand_mask = smoothstep(0.28f, 0.92f, strand);
  entgfx::Vec3 dark = material.base_color * entgfx::Vec3{0.64f, 0.58f, 0.50f};
  entgfx::Vec3 light = material.base_color * entgfx::Vec3{1.22f, 1.14f, 0.96f};
  return mixVec(dark, light, strand_mask * (0.56f + material.pattern_contrast * 0.28f));
}

entgfx::Vec3 caveWebAlbedo(const entgfx::Material &material, const entgfx::Vec3 world_position,
                          const entgfx::Vec3 normal, const entgfx::Vec2 uv) {
  const float along = uv.x * std::max(material.pattern_scale.y, 0.001f);
  const float across = std::abs(uv.y - 0.5f) * 2.0f;
  const float fiber =
      ridge(0.5f + 0.5f * std::sin(along * 0.72f +
                                   projectedFbm(material, world_position, normal, 0.88f, 211.0f) *
                                       4.6f));
  const float core = 1.0f - smoothstep(0.18f, 1.0f, across);
  const float dust = projectedFbm(material, world_position, normal, 1.42f, 227.0f);
  const float glint = smoothstep(0.58f, 0.98f, fiber * core);
  const entgfx::Vec3 shadow = material.base_color * entgfx::Vec3{0.62f, 0.66f, 0.66f};
  const entgfx::Vec3 silk = material.base_color * entgfx::Vec3{1.22f, 1.24f, 1.16f};
  const entgfx::Vec3 pearl = material.base_color + entgfx::Vec3{0.08f, 0.09f, 0.075f};
  return entgfx::clamp(mixVec(mixVec(shadow, silk, core * 0.72f + dust * 0.16f), pearl, glint),
                      0.0f, 4.0f);
}

entgfx::Vec3 caveSkitterEyeAlbedo(const entgfx::Material &material,
                                 const entgfx::Vec3 world_position, const entgfx::Vec3 normal);

entgfx::Vec3 caveSkitterChitinAlbedo(const entgfx::Material &material,
                                    const entgfx::Vec3 world_position, const entgfx::Vec3 normal,
                                    const entgfx::Vec2 uv) {
  if (uv.x > 0.90f && uv.y < 0.28f) {
    return caveSkitterEyeAlbedo(material, world_position, normal);
  }
  const float texel_x = std::floor(uv.x * std::max(material.pattern_scale.x, 1.0f));
  const float texel_y = std::floor(uv.y * std::max(material.pattern_scale.y, 1.0f));
  const float texel = fractValue(std::sin(texel_x * 12.9898f + texel_y * 78.233f) * 43758.5453f);
  const float ridge_a = ridge(projectedFbm(material, world_position, normal, 1.35f, 241.0f));
  const float band =
      0.5f + 0.5f * std::sin((texel_y * 0.92f + std::floor(texel_x * 0.25f)) * 1.73f);
  const float shell = smoothstep(0.20f, 0.92f, ridge_a * 0.56f + band * 0.30f + texel * 0.14f);
  const float center_spot =
      (1.0f - smoothstep(0.04f, 0.18f, std::abs(uv.x - 0.50f))) *
      smoothstep(0.10f, 0.54f, uv.y) * (1.0f - smoothstep(0.78f, 0.98f, uv.y));
  const float leg_band = smoothstep(0.62f, 0.96f, ridge(0.5f + 0.5f * std::sin(texel_y * 2.45f)));
  const float oil = projectedFbm(material, world_position + normal * 0.05f, normal, 0.78f, 263.0f);
  const entgfx::Vec3 under = material.base_color * entgfx::Vec3{0.44f, 0.34f, 0.30f};
  const entgfx::Vec3 lacquer = material.base_color * entgfx::Vec3{1.54f, 1.04f, 0.78f};
  const entgfx::Vec3 warm_mark = material.base_color + entgfx::Vec3{0.070f, 0.020f, 0.010f};
  const entgfx::Vec3 dark_band = material.base_color * entgfx::Vec3{0.22f, 0.18f, 0.18f};
  const entgfx::Vec3 cool_sheen = material.base_color + entgfx::Vec3{0.042f, 0.050f, 0.060f};
  entgfx::Vec3 albedo = mixVec(under, lacquer, shell);
  albedo = mixVec(albedo, warm_mark, center_spot * 0.58f);
  albedo = mixVec(albedo, dark_band, leg_band * (0.18f + texel * 0.12f));
  albedo = mixVec(albedo, cool_sheen, oil * 0.26f);
  return entgfx::clamp(albedo, 0.0f, 4.0f);
}

entgfx::Vec3 caveSkitterEyeAlbedo(const entgfx::Material &material,
                                 const entgfx::Vec3 world_position, const entgfx::Vec3 normal) {
  const float wet = smoothstep(0.45f, 0.96f,
                               projectedFbm(material, world_position, normal, 1.9f, 283.0f));
  return entgfx::clamp(material.base_color * (0.62f + wet * 0.44f) +
                          material.emission_color * (0.28f + wet * 0.34f),
                      0.0f, 4.0f);
}

entgfx::Vec3 foliageAlbedo(const entgfx::Material &material, const entgfx::Vec3 world_position,
                          const entgfx::Vec3 normal, const entgfx::Vec2 uv) {
  const float blade_height = saturate(uv.y);
  const float root_weight = 1.0f - smoothstep(0.04f, 0.36f, blade_height);
  const float tip_weight = smoothstep(0.48f, 1.0f, blade_height);
  const float central_vein = 1.0f - smoothstep(0.025f, 0.22f, std::abs(uv.x - 0.5f));
  const float strand =
      0.5f + 0.5f * std::sin((uv.y * material.pattern_scale.y + uv.x * 2.0f) * kTau);
  const float mottling = projectedFbm(material, world_position, normal, 0.64f, 109.0f);
  const float fiber = ridge(projectedFbm(material, world_position, normal, 1.22f, 113.0f));
  const entgfx::Vec3 root = material.base_color * entgfx::Vec3{0.50f, 0.66f, 0.38f};
  const entgfx::Vec3 mid = material.base_color * entgfx::Vec3{0.82f, 1.08f, 0.58f};
  const entgfx::Vec3 tip = material.base_color * entgfx::Vec3{1.18f, 1.30f, 0.72f};
  entgfx::Vec3 blade = mixVec(root, mid, smoothstep(0.02f, 0.72f, blade_height));
  blade = mixVec(blade, tip, tip_weight * (0.42f + mottling * 0.28f));
  blade = blade * (0.88f + mottling * 0.18f + fiber * 0.08f + strand * 0.05f);
  blade = mixVec(blade, blade * entgfx::Vec3{1.26f, 1.34f, 0.88f}, central_vein * 0.18f);
  return entgfx::clamp(mixVec(blade, blade * 0.72f, root_weight * 0.34f), 0.0f, 4.0f);
}

entgfx::Vec3 liquidAlbedo(const entgfx::Material &material, const entgfx::Vec3 world_position,
                         const entgfx::Vec2 uv, const double frame_seconds) {
  const float time = static_cast<float>(frame_seconds);
  const float wave_a =
      0.5f +
      0.5f * std::sin((uv.x * material.pattern_scale.x + uv.y * material.pattern_scale.y) * 5.4f +
                      time * 1.35f);
  const float wave_b =
      valueNoise({world_position.x * 0.58f + time * 0.22f, world_position.y * 0.12f,
                  world_position.z * 0.72f - time * 0.17f});
  const entgfx::Vec3 deep = material.base_color * entgfx::Vec3{0.55f, 0.88f, 0.96f};
  const entgfx::Vec3 glint = material.base_color + entgfx::Vec3{0.08f, 0.20f, 0.22f};
  return mixVec(deep, glint, smoothstep(0.45f, 0.94f, wave_a * 0.64f + wave_b * 0.36f));
}

entgfx::Vec3 amberAlbedo(const entgfx::Material &material, const entgfx::Vec3 world_position,
                        const entgfx::Vec3 normal) {
  const float streak = ridge(projectedFbm(material, world_position, normal, 0.44f, 127.0f));
  const float cloud = projectedFbm(material, world_position, normal, 1.10f, 131.0f);
  const entgfx::Vec3 honey = material.base_color * entgfx::Vec3{1.30f, 0.96f, 0.56f};
  const entgfx::Vec3 smoke = material.base_color * entgfx::Vec3{0.62f, 0.42f, 0.28f};
  return mixVec(smoke, honey, smoothstep(0.25f, 0.92f, cloud)) +
         material.emission_color * (0.08f + smoothstep(0.70f, 0.98f, streak) * 0.16f);
}

entgfx::Vec3 pbrNeutralTonemap(entgfx::Vec3 color) {
  constexpr float start_compression = 0.76f;
  constexpr float desaturation = 0.15f;

  const float x = std::min(color.x, std::min(color.y, color.z));
  const float offset = x < 0.08f ? x - 6.25f * x * x : 0.04f;
  color = color - entgfx::Vec3{offset, offset, offset};

  const float peak = std::max(color.x, std::max(color.y, color.z));
  if (peak < start_compression) {
    return color;
  }

  constexpr float d = 1.0f - start_compression;
  const float new_peak = 1.0f - d * d / (peak + d - start_compression);
  color = color * (new_peak / std::max(peak, 0.0001f));
  const float g = 1.0f - 1.0f / (desaturation * (peak - new_peak) + 1.0f);
  return mixVec(color, {new_peak, new_peak, new_peak}, g);
}

int toneMapperUniform(const entgfx::RendererSettings &settings) {
  if (settings.use_aces_tonemap) {
    return 0;
  }
  switch (settings.pipeline.tone_mapper) {
  case entgfx::ToneMapper::FilmicAces:
    return 0;
  case entgfx::ToneMapper::PbrNeutral:
    return 1;
  case entgfx::ToneMapper::Reinhard:
    return 2;
  }
  return 1;
}

entgfx::Vec3 toneMapColor(const entgfx::Vec3 color, const int tone_mapper) {
  if (tone_mapper == 0) {
    return entgfx::aces_tonemap(color);
  }
  if (tone_mapper == 2) {
    return entgfx::reinhard_tonemap(color);
  }
  return pbrNeutralTonemap(color);
}

float luminance(const entgfx::Vec3 color) {
  return color.x * 0.2126f + color.y * 0.7152f + color.z * 0.0722f;
}

entgfx::Vec3 applyVisualGrade(entgfx::Vec3 color, const entgfx::AtmosphereSettings &atmosphere) {
  const float pre_grade_luma = luminance(color);
  color = mixVec(color, color * atmosphere.shadow_tint,
                 std::clamp(atmosphere.shadow_tint_strength, 0.0f, 1.0f) *
                     (1.0f - smoothstep(0.05f, 0.48f, pre_grade_luma)));
  color = mixVec(color, color * atmosphere.highlight_tint,
                 std::clamp(atmosphere.highlight_tint_strength, 0.0f, 1.0f) *
                     smoothstep(0.52f, 1.45f, pre_grade_luma));
  const float post_grade_luma = luminance(color);
  color = mixVec({post_grade_luma, post_grade_luma, post_grade_luma}, color,
                 std::clamp(atmosphere.saturation, 0.0f, 2.0f));
  color = (color - entgfx::Vec3{0.5f, 0.5f, 0.5f}) * std::max(atmosphere.contrast, 0.0f) +
          entgfx::Vec3{0.5f, 0.5f, 0.5f};
  return color;
}

entgfx::Vec3 applyProceduralLayer(const entgfx::Material &material, const entgfx::Vec3 world_position,
                                 const entgfx::Vec3 normal, const entgfx::Vec3 color) {
  const float macro_strength = std::max(material.procedural.macro_variation, 0.0f);
  const float wetness = std::clamp(material.procedural.wetness, 0.0f, 1.0f);
  const float height_shading = std::max(material.procedural.height_shading, 0.0f);
  if (macro_strength <= 0.0001f && wetness <= 0.0001f && height_shading <= 0.0001f) {
    return color;
  }

  const float detail = std::max(material.detail_scale, 0.001f);
  const float broad =
      valueNoise(world_position * (0.10f + detail * 0.014f) + entgfx::Vec3{23.7f, 0.0f, -11.3f});
  const float fine = valueNoise(world_position * (0.48f + detail * 0.036f) + normal * 0.31f);
  const float surface_lift = smoothstep(0.18f, 0.86f, normal.y);
  const float variation = 1.0f + (broad - 0.5f) * macro_strength * 0.28f +
                          (fine - 0.5f) * macro_strength * 0.12f +
                          surface_lift * height_shading * 0.045f;
  const entgfx::Vec3 damp_color =
      mixVec(color * 0.70f, color * entgfx::Vec3{0.80f, 0.86f, 0.92f}, surface_lift * 0.45f);
  return entgfx::clamp(mixVec(color * variation, damp_color, wetness * (0.18f + fine * 0.18f)), 0.0f,
                      4.0f);
}

entgfx::Vec3 proceduralSurfaceNormal(const entgfx::Material &material,
                                    const entgfx::Vec3 world_position, const entgfx::Vec3 normal) {
  if (material.surface_pattern == entgfx::SurfacePattern::ContactShadow ||
      material.surface_pattern == entgfx::SurfacePattern::WaterSurface) {
    return normal;
  }

  const float terrain_gain = isTerrainPattern(material.surface_pattern) ? 0.44f : 0.28f;
  const float inferred_strength = material.detail_strength * terrain_gain;
  const float explicit_strength = std::max(material.procedural.micro_normal_strength, 0.0f);
  const float strength = std::clamp(std::max(inferred_strength, explicit_strength), 0.0f, 1.20f);
  if (strength <= 0.0001f) {
    return normal;
  }

  const float detail = std::max(material.detail_scale, 0.001f);
  const float macro_gain = 1.0f + std::max(material.procedural.macro_variation, 0.0f) * 0.34f;
  const entgfx::Vec3 p =
      world_position * (0.55f * detail * macro_gain) +
      entgfx::Vec3{static_cast<float>(static_cast<int>(material.surface_pattern)) * 0.23f, 0.0f,
                  static_cast<float>(static_cast<int>(material.surface_pattern)) * 0.41f};
  const entgfx::Vec3 bump{valueNoise(p + entgfx::Vec3{11.1f, 2.3f, 0.7f}) - 0.5f,
                         (valueNoise(p + entgfx::Vec3{5.7f, 13.1f, 3.2f}) - 0.5f) * 0.35f,
                         valueNoise(p + entgfx::Vec3{2.9f, 7.4f, 17.6f}) - 0.5f};
  const entgfx::Vec3 adjusted = entgfx::normalize(normal + bump * strength);
  return entgfx::length(adjusted) > 0.0001f ? adjusted : normal;
}

entgfx::Vec3 materialAlbedo(const entgfx::Material &material, const entgfx::Vec3 world_position,
                           const entgfx::Vec3 normal, const entgfx::Vec2 uv,
                           const double frame_seconds) {
  if (material.surface_pattern == entgfx::SurfacePattern::ContactShadow) {
    return {0.0f, 0.0f, 0.0f};
  }

  const float pattern_id = static_cast<float>(static_cast<int>(material.surface_pattern));
  const entgfx::Vec3 sample_position =
      patternSamplePosition(material, world_position, normal, frame_seconds);
  const float broad = valueNoise(sample_position * 0.37f);
  const float fine = valueNoise(sample_position * 1.91f);
  const float procedural_weight =
      material.surface_pattern == entgfx::SurfacePattern::None
          ? saturate(material.detail_strength + material.procedural.macro_variation * 0.22f)
          : saturate(0.16f + material.detail_strength + material.pattern_contrast * 0.55f +
                     std::abs(material.pattern_depth) * 1.35f +
                     material.procedural.macro_variation * 0.24f);
  if (isTerrainPattern(material.surface_pattern)) {
    return applyProceduralLayer(material, world_position, normal,
                                terrainLayeredAlbedo(material, world_position, normal));
  }
  switch (material.surface_pattern) {
  case entgfx::SurfacePattern::CourseCells:
  case entgfx::SurfacePattern::WeatheredStone:
    return applyProceduralLayer(
        material, world_position, normal,
        entgfx::clamp(structuredStoneAlbedo(material, world_position, normal), 0.0f, 4.0f));
  case entgfx::SurfacePattern::CaveRock:
    return applyProceduralLayer(material, world_position, normal,
                                caveRockAlbedo(material, world_position, normal));
  case entgfx::SurfacePattern::CoalVein:
    return applyProceduralLayer(material, world_position, normal,
                                coalVeinAlbedo(material, world_position, normal));
  case entgfx::SurfacePattern::WaterSurface:
    return applyProceduralLayer(material, world_position, normal,
                                liquidAlbedo(material, world_position, uv, frame_seconds));
  case entgfx::SurfacePattern::FurFibers:
  case entgfx::SurfacePattern::FiberStrands:
    return entgfx::clamp(
        organicFiberAlbedo(material, world_position, normal, uv, pattern_id + 151.0f), 0.0f, 4.0f);
  case entgfx::SurfacePattern::CaveWeb:
    return applyProceduralLayer(material, world_position, normal,
                                caveWebAlbedo(material, world_position, normal, uv));
  case entgfx::SurfacePattern::CaveSkitterChitin:
    return applyProceduralLayer(material, world_position, normal,
                                caveSkitterChitinAlbedo(material, world_position, normal, uv));
  case entgfx::SurfacePattern::CaveSkitterEye:
    return caveSkitterEyeAlbedo(material, world_position, normal);
  case entgfx::SurfacePattern::Foliage:
    return applyProceduralLayer(
        material, world_position, normal,
        entgfx::clamp(foliageAlbedo(material, world_position, normal, uv), 0.0f, 4.0f));
  case entgfx::SurfacePattern::AmberResin:
    return entgfx::clamp(amberAlbedo(material, world_position, normal), 0.0f, 4.0f);
  case entgfx::SurfacePattern::PaintedWood: {
    const float grain = ridge(projectedFbm(material, world_position, normal, 0.52f, 167.0f));
    const float rings =
        0.5f + 0.5f * std::sin((world_position.y * material.pattern_scale.y +
                                world_position.x * 0.28f + world_position.z * 0.19f) *
                                   2.2f +
                               grain * 3.4f);
    const entgfx::Vec3 dark = material.base_color * entgfx::Vec3{0.62f, 0.48f, 0.34f};
    const entgfx::Vec3 warm = material.base_color * entgfx::Vec3{1.18f, 0.96f, 0.68f};
    return entgfx::clamp(mixVec(dark, warm, smoothstep(0.18f, 0.92f, rings)), 0.0f, 4.0f);
  }
  case entgfx::SurfacePattern::FeatherVanes: {
    const float central = 1.0f - smoothstep(0.025f, 0.18f, std::abs(uv.x - 0.5f));
    const float barb =
        0.5f + 0.5f * std::sin((uv.y * material.pattern_scale.y + uv.x * 3.0f) * kTau);
    entgfx::Vec3 feather = mixVec(material.base_color * 0.72f, material.base_color * 1.22f,
                                 smoothstep(0.26f, 0.88f, barb));
    return entgfx::clamp(mixVec(feather, feather * 1.35f, central * 0.34f), 0.0f, 4.0f);
  }
  case entgfx::SurfacePattern::IridescentScales:
  case entgfx::SurfacePattern::ReptileScales: {
    const entgfx::Vec2 scaled{uv.x * std::max(material.pattern_scale.x, 0.001f),
                             uv.y * std::max(material.pattern_scale.y, 0.001f)};
    const entgfx::Vec2 cell{fractValue(scaled.x), fractValue(scaled.y)};
    const float shell = smoothstep(0.18f, 0.50f, 1.0f - length(cell - entgfx::Vec2{0.5f, 0.5f}));
    const float hue_shift = projectedFbm(material, world_position, normal, 1.10f, 181.0f);
    entgfx::Vec3 scale_color =
        mixVec(material.base_color * entgfx::Vec3{0.66f, 0.82f, 0.76f},
               material.base_color * entgfx::Vec3{1.22f, 1.02f, 0.68f}, hue_shift);
    return entgfx::clamp(mixVec(material.base_color * 0.62f, scale_color, shell), 0.0f, 4.0f);
  }
  case entgfx::SurfacePattern::TwigNest:
    return entgfx::clamp(organicFiberAlbedo(material, world_position, normal, uv, 193.0f) *
                            entgfx::Vec3{0.90f, 0.78f, 0.58f},
                        0.0f, 4.0f);
  case entgfx::SurfacePattern::None:
  case entgfx::SurfacePattern::GrassSoil:
  case entgfx::SurfacePattern::SoilPath:
  case entgfx::SurfacePattern::TerrainBlend:
  case entgfx::SurfacePattern::LayeredTerrain:
  case entgfx::SurfacePattern::ContactShadow:
    break;
  }
  const float uv_wave = std::sin((uv.x * std::max(material.pattern_scale.x, 0.001f) +
                                  uv.y * std::max(material.pattern_scale.y, 0.001f)) *
                                 6.2831853f);
  const entgfx::Vec3 macro_position =
      world_position * 0.22f + entgfx::Vec3{pattern_id * 0.41f, 0.0f, pattern_id * 0.29f};
  const float macro_patch = valueNoise(macro_position);
  const float macro_stain = valueNoise(macro_position * 0.43f + entgfx::Vec3{2.7f, 0.0f, -1.9f});
  const float upward_surface = smoothstep(0.50f, 0.92f, normal.y);
  const float macro_weight =
      saturate((material.detail_strength * 0.20f + material.pattern_contrast * 0.12f) *
               (0.45f + upward_surface * 0.55f));
  const float variation = 0.82f + broad * 0.24f + fine * 0.10f + uv_wave * 0.04f +
                          (macro_patch * 0.18f - macro_stain * 0.08f) * macro_weight;
  return applyProceduralLayer(
      material, world_position, normal,
      entgfx::clamp(material.base_color * std::lerp(1.0f, variation, procedural_weight), 0.0f,
                   4.0f));
}

entgfx::Vec3 shadeVertex(const entgfx::Material &material, const entgfx::Vec3 world_position,
                        entgfx::Vec3 normal, const entgfx::Vec2 uv, const float vertex_ao,
                        const entgfx::Vec3 camera_position, const entgfx::RendererSettings &settings,
                        const double frame_seconds) {
  normal = entgfx::normalize(normal);
  if (entgfx::length(normal) <= 0.0001f) {
    normal = {0.0f, 1.0f, 0.0f};
  }
  if (settings.procedural_surface_normals) {
    normal = proceduralSurfaceNormal(material, world_position, normal);
  }

  const entgfx::Vec3 albedo = materialAlbedo(material, world_position, normal, uv, frame_seconds);
  const float sky_factor = saturate(normal.y * 0.5f + 0.5f);
  const entgfx::Vec3 ambient_color =
      mixVec(settings.ground_ambient_color, settings.sky_ambient_color, sky_factor);
  const float geometry_ao =
      std::clamp(material.ambient_occlusion * std::clamp(vertex_ao, 0.0f, 1.0f), 0.0f, 1.0f);
  const float ambient_level =
      std::max(settings.ambient_strength * geometry_ao, settings.ambient_floor);
  entgfx::Vec3 color = ambient_color * albedo * ambient_level + albedo * 0.035f;

  const entgfx::Vec3 view = entgfx::normalize(camera_position - world_position);
  const float metallic = std::clamp(material.metallic, 0.0f, 1.0f);
  const float perceptual_roughness = std::clamp(material.roughness, 0.045f, 1.0f);
  const float n_dot_v = std::max(entgfx::dot(normal, view), 0.001f);
  const entgfx::Vec3 f0 = mixVec({0.04f, 0.04f, 0.04f}, albedo, metallic);
  const float alpha = perceptual_roughness * perceptual_roughness;
  const float alpha2 = std::max(alpha * alpha, 0.0005f);
  const float k = ((perceptual_roughness + 1.0f) * (perceptual_roughness + 1.0f)) * 0.125f;

  const auto add_light = [&](const entgfx::Vec3 light_dir, const entgfx::Vec3 radiance) {
    const entgfx::Vec3 half_vector = entgfx::normalize(light_dir + view);
    const float n_dot_l = std::max(entgfx::dot(normal, light_dir), 0.0f);
    const float n_dot_h = std::max(entgfx::dot(normal, half_vector), 0.0f);
    const float h_dot_v = std::max(entgfx::dot(half_vector, view), 0.0f);
    const float distribution_denominator = n_dot_h * n_dot_h * (alpha2 - 1.0f) + 1.0f;
    const float distribution =
        alpha2 /
        std::max(3.14159265f * distribution_denominator * distribution_denominator, 0.001f);
    const float geometry_l = n_dot_l / std::max(n_dot_l * (1.0f - k) + k, 0.001f);
    const float geometry_v = n_dot_v / std::max(n_dot_v * (1.0f - k) + k, 0.001f);
    const entgfx::Vec3 fresnel =
        f0 + (entgfx::Vec3{1.0f, 1.0f, 1.0f} - f0) * std::pow(1.0f - h_dot_v, 5.0f);
    const entgfx::Vec3 specular = fresnel * (distribution * geometry_l * geometry_v);
    const entgfx::Vec3 diffuse = albedo * ((1.0f - metallic) * 0.82f);
    color = color + (diffuse + specular) * (radiance * n_dot_l);
  };

  if (settings.sun_light.enabled && settings.sun_light.intensity > 0.0f) {
    const entgfx::Vec3 sun_dir = entgfx::normalize(settings.sun_light.direction_to_light);
    if (entgfx::length(sun_dir) > 0.0001f) {
      add_light(sun_dir, settings.sun_light.color * settings.sun_light.intensity);
    }
  }

  for (const entgfx::Light &light : settings.light_rig) {
    const entgfx::Vec3 light_vector = light.position - world_position;
    const float distance_sq = std::max(entgfx::dot(light_vector, light_vector), 0.0001f);
    const entgfx::Vec3 light_dir = entgfx::normalize(light_vector);
    const float softened_distance =
        std::max(distance_sq, light.source_radius * light.source_radius + 0.0001f);
    const entgfx::Vec3 radiance = light.color * (light.intensity / softened_distance);
    add_light(light_dir, radiance);
  }

  if (settings.grounding.enabled && settings.grounding.surface_occlusion_strength > 0.0f) {
    const float height = std::max(settings.grounding.surface_occlusion_height, 0.001f);
    const float above_reference = std::max(world_position.y - settings.grounding.reference_y, 0.0f);
    const float proximity = 1.0f - smoothstep(0.0f, height, above_reference);
    const float vertical_receiver = (1.0f - smoothstep(0.48f, 0.92f, normal.y)) * 0.35f;
    const float raw = 1.0f - std::clamp(proximity * vertical_receiver *
                                            settings.grounding.surface_occlusion_strength,
                                        0.0f, 0.70f);
    color = color * mixVec({1.0f, 1.0f, 1.0f},
                           {std::max(raw, settings.grounding.surface_occlusion_min),
                            std::max(raw, settings.grounding.surface_occlusion_min),
                            std::max(raw, settings.grounding.surface_occlusion_min)},
                           settings.grounding.surface_occlusion_mix);
  }

  if (settings.atmosphere.enabled) {
    const float fog_range =
        std::max(settings.atmosphere.fog_end - settings.atmosphere.fog_start, 0.001f);
    const float fog = smoothstep(0.0f, 1.0f,
                                 (entgfx::length(camera_position - world_position) -
                                  settings.atmosphere.fog_start) /
                                     fog_range) *
                      std::clamp(settings.atmosphere.fog_strength, 0.0f, 1.0f);
    color = mixVec(color, settings.atmosphere.fog_color, fog);
  }

  color = applyVisualGrade(color, settings.atmosphere);
  color = color + material.emission_color * material.emission_strength;
  color = color * settings.exposure;
  color = toneMapColor(color, toneMapperUniform(settings));
  return entgfx::gamma_encode(entgfx::clamp(color, 0.0f, 1.0f));
}

entgfx::FrameColor shadedFrameColor(const entgfx::Material &material,
                                   const entgfx::Vec3 world_position, const entgfx::Vec3 normal,
                                   const entgfx::Vec2 uv, const float vertex_ao,
                                   const entgfx::Vec3 camera_position,
                                   const entgfx::RendererSettings &settings,
                                   const double frame_seconds, const float opacity) {
  return entgfx::frameColor(shadeVertex(material, world_position, normal, uv, vertex_ao,
                                       camera_position, settings, frame_seconds),
                           opacity);
}

bool containsViewerCullVolume(const entgfx::ViewerCullVolume &volume, const entgfx::Vec3 point) {
  if (!volume.enabled || volume.half_extents.x <= 0.0f || volume.half_extents.y <= 0.0f ||
      volume.half_extents.z <= 0.0f) {
    return false;
  }
  const entgfx::Vec3 delta = point - volume.center;
  return std::abs(delta.x) <= volume.half_extents.x && std::abs(delta.y) <= volume.half_extents.y &&
         std::abs(delta.z) <= volume.half_extents.z;
}

entgfx::FaceCullMode objectCullMode(const entgfx::RenderObject &object,
                                   const entgfx::Vec3 camera_position,
                                   const bool pipeline_back_face_culling) {
  if (!pipeline_back_face_culling || entgfx::isDoubleSidedMaterial(object.material)) {
    return entgfx::FaceCullMode::None;
  }
  if (containsViewerCullVolume(object.viewer_cull_volume, camera_position)) {
    return object.viewer_cull_volume.inside;
  }
  if (object.viewer_cull_volume.enabled) {
    return object.viewer_cull_volume.outside;
  }
  return object.material.cull_mode;
}

bool isContactShadowUtility(const entgfx::RenderObject &object) {
  return object.material.surface_pattern == entgfx::SurfacePattern::ContactShadow;
}

LocalBounds primitiveLocalBounds(const entgfx::MeshPrimitive primitive) {
  switch (primitive) {
  case entgfx::MeshPrimitive::Box:
    return {{-0.5f, -0.5f, -0.5f}, {0.5f, 0.5f, 0.5f}};
  case entgfx::MeshPrimitive::Sphere:
  case entgfx::MeshPrimitive::Rock:
    return {{-1.0f, -1.0f, -1.0f}, {1.0f, 1.0f, 1.0f}};
  case entgfx::MeshPrimitive::Crystal:
    return {{-1.0f, -0.9f, -0.9f}, {1.0f, 0.9f, 0.9f}};
  case entgfx::MeshPrimitive::RuinBlock:
    return {{-0.56f, -0.54f, -0.55f}, {0.56f, 0.54f, 0.55f}};
  case entgfx::MeshPrimitive::Pillar:
    return {{-1.18f, -0.5f, -1.18f}, {1.18f, 0.5f, 1.18f}};
  case entgfx::MeshPrimitive::Plane:
    return {{-6.0f, 0.0f, -6.0f}, {6.0f, 0.0f, 6.0f}};
  }
  return {{-1.0f, -1.0f, -1.0f}, {1.0f, 1.0f, 1.0f}};
}

LocalBounds customMeshLocalBounds(const entgfx::CpuMesh &mesh) {
  if (mesh.vertices.empty()) {
    return {};
  }
  LocalBounds bounds{mesh.vertices.front().position, mesh.vertices.front().position};
  for (const entgfx::Vertex &vertex : mesh.vertices) {
    bounds.min.x = std::min(bounds.min.x, vertex.position.x);
    bounds.min.y = std::min(bounds.min.y, vertex.position.y);
    bounds.min.z = std::min(bounds.min.z, vertex.position.z);
    bounds.max.x = std::max(bounds.max.x, vertex.position.x);
    bounds.max.y = std::max(bounds.max.y, vertex.position.y);
    bounds.max.z = std::max(bounds.max.z, vertex.position.z);
  }
  return bounds;
}

LocalBounds objectLocalBounds(const entgfx::RenderObject &object) {
  return object.custom_mesh != nullptr ? customMeshLocalBounds(*object.custom_mesh)
                                       : primitiveLocalBounds(object.primitive);
}

float localMaxAbs(const float min_value, const float max_value) {
  return std::max(std::abs(min_value), std::abs(max_value));
}

float objectFootY(const entgfx::RenderObject &object, const LocalBounds &bounds) {
  return object.transform.position.y + bounds.min.y * object.transform.scale.y;
}

entgfx::Vec2 objectContactHalfExtents(const entgfx::RenderObject &object, const LocalBounds &bounds) {
  return {localMaxAbs(bounds.min.x, bounds.max.x) * std::abs(object.transform.scale.x),
          localMaxAbs(bounds.min.z, bounds.max.z) * std::abs(object.transform.scale.z)};
}

bool canCastContactShadow(const entgfx::RenderObject &object,
                          const entgfx::GroundingSettings &grounding) {
  const bool requested =
      object.casts_contact_shadow || (grounding.auto_contact_shadows && object.auto_contact_shadow);
  if (!grounding.enabled || !grounding.contact_shadows || !requested) {
    return false;
  }
  if (object.material.render_role == entgfx::MaterialRenderRole::SupportSurface) {
    return false;
  }
  if (entgfx::classifyMaterialRenderQueue(object.material) != entgfx::MaterialRenderQueue::Opaque ||
      isContactShadowUtility(object)) {
    return false;
  }
  if (object.custom_mesh == nullptr && object.primitive == entgfx::MeshPrimitive::Plane) {
    return false;
  }

  const LocalBounds bounds = objectLocalBounds(object);
  const entgfx::Vec2 half_extents = objectContactHalfExtents(object, bounds);
  const float min_radius = std::max(grounding.contact_shadow_min_radius, 0.0f);
  const float max_radius = std::max(grounding.contact_shadow_max_radius, min_radius);
  const float raw_radius = std::max(half_extents.x, half_extents.y) *
                           grounding.contact_shadow_radius_scale *
                           object.contact_shadow_radius_scale;
  if (raw_radius < min_radius || raw_radius > max_radius) {
    return false;
  }

  const float receiver_delta = std::abs(objectFootY(object, bounds) - grounding.reference_y);
  return receiver_delta <= std::max(grounding.contact_shadow_receiver_height, 0.0f);
}

entgfx::RenderObject contactShadowObjectFor(const entgfx::RenderObject &object,
                                           const entgfx::GroundingSettings &grounding) {
  const LocalBounds bounds = objectLocalBounds(object);
  const entgfx::Vec2 half_extents = objectContactHalfExtents(object, bounds);
  const float min_radius = std::max(grounding.contact_shadow_min_radius, 0.0f);
  const float max_radius = std::max(grounding.contact_shadow_max_radius, min_radius);
  const float raw_radius = std::max(half_extents.x, half_extents.y) *
                           grounding.contact_shadow_radius_scale *
                           object.contact_shadow_radius_scale;
  const float radius = std::clamp(raw_radius, min_radius, max_radius);
  const float footprint_x = std::clamp(half_extents.x * grounding.contact_shadow_radius_scale *
                                           object.contact_shadow_radius_scale,
                                       min_radius, radius);
  const float footprint_z = std::clamp(half_extents.y * grounding.contact_shadow_radius_scale *
                                           object.contact_shadow_radius_scale,
                                       min_radius, radius);
  const float foot_y = objectFootY(object, bounds);
  const float receiver_delta = std::abs(foot_y - grounding.reference_y);
  const float fade = 1.0f - smoothstep(grounding.contact_shadow_receiver_height * 0.72f,
                                       grounding.contact_shadow_receiver_height, receiver_delta);

  entgfx::RenderObject shadow;
  shadow.name = "Procedural contact shadow";
  shadow.primitive = entgfx::MeshPrimitive::Plane;
  shadow.transform.position = {object.transform.position.x,
                               foot_y + grounding.contact_shadow_receiver_bias,
                               object.transform.position.z};
  shadow.transform.rotation = {0.0f, object.transform.rotation.y, 0.0f};
  shadow.transform.scale = {footprint_x, 1.0f, footprint_z};
  shadow.material.base_color = {0.0f, 0.0f, 0.0f};
  shadow.material.roughness = 1.0f;
  shadow.material.opacity = std::clamp(
      grounding.contact_shadow_strength * object.contact_shadow_strength * fade, 0.0f, 0.85f);
  shadow.material.surface_pattern = entgfx::SurfacePattern::ContactShadow;
  shadow.material.alpha_mode = entgfx::MaterialAlphaMode::Blend;
  shadow.material.depth_write = entgfx::MaterialDepthWrite::Disabled;
  shadow.material.camera_occlusion = entgfx::CameraOcclusionPolicy::Solid;
  shadow.material.double_sided = true;
  shadow.casts_contact_shadow = false;
  shadow.camera_occlusion_fade = false;
  return shadow;
}

ProjectedVertex projectVertex(const entgfx::Vertex &vertex, const entgfx::Mat4 &model,
                              const entgfx::Mat4 &model_view_projection, const int width,
                              const int height) {
  const Vec4f clip = transformPoint4(model_view_projection, vertex.position);
  if (clip.w <= 0.0001f) {
    return {};
  }

  const float inv_w = 1.0f / clip.w;
  const float ndc_x = clip.x * inv_w;
  const float ndc_y = clip.y * inv_w;
  const float ndc_z = clip.z * inv_w;
  if (ndc_z < -1.0f || ndc_z > 1.0f || ndc_x < -2.0f || ndc_x > 2.0f || ndc_y < -2.0f ||
      ndc_y > 2.0f) {
    return {};
  }

  return {
      .valid = true,
      .world_position = entgfx::transformPoint(model, vertex.position),
      .normal = entgfx::normalize(entgfx::transformVector(model, vertex.normal)),
      .uv = vertex.uv,
      .ambient_occlusion = vertex.ambient_occlusion,
      .x = (ndc_x * 0.5f + 0.5f) * static_cast<float>(width),
      .y = (1.0f - (ndc_y * 0.5f + 0.5f)) * static_cast<float>(height),
      .depth = ndc_z * 0.5f + 0.5f,
  };
}

bool shouldCullTriangle(const ProjectedVertex &a, const ProjectedVertex &b,
                        const ProjectedVertex &c, const entgfx::Vec3 camera_position,
                        const entgfx::FaceCullMode cull_mode) {
  if (cull_mode == entgfx::FaceCullMode::None) {
    return false;
  }
  const entgfx::Vec3 face_normal = entgfx::normalize(
      entgfx::cross(b.world_position - a.world_position, c.world_position - a.world_position));
  const entgfx::Vec3 centroid = (a.world_position + b.world_position + c.world_position) / 3.0f;
  const bool front_facing = entgfx::dot(face_normal, camera_position - centroid) >= 0.0f;
  return (cull_mode == entgfx::FaceCullMode::Back && !front_facing) ||
         (cull_mode == entgfx::FaceCullMode::Front && front_facing);
}

void drawMesh(entgfx::SoftwareFrameBuffer &framebuffer, const entgfx::CpuMesh &mesh,
              const entgfx::RenderObject &object, const entgfx::OrbitCamera &camera,
              const entgfx::RendererSettings &settings, const double frame_seconds,
              const float opacity, std::size_t &draw_calls) {
  if (mesh.vertices.empty() || mesh.indices.empty() || opacity <= 0.003f) {
    return;
  }

  const entgfx::Vec3 camera_position = camera.position();
  const entgfx::Mat4 model =
      settings.animate_scene && object.spin_rate != 0.0f
          ? object.transform.matrix() *
                entgfx::rotation_y(static_cast<float>(frame_seconds) * object.spin_rate)
          : object.transform.matrix();
  const float aspect_ratio = static_cast<float>(std::max(framebuffer.width(), 1)) /
                             static_cast<float>(std::max(framebuffer.height(), 1));
  const entgfx::Mat4 model_view_projection =
      camera.projectionMatrix(aspect_ratio) * camera.viewMatrix() * model;
  const entgfx::FaceCullMode cull_mode =
      objectCullMode(object, camera_position, settings.pipeline.back_face_culling);
  const bool alpha_blend =
      opacity < 0.999f || entgfx::classifyMaterialRenderQueue(object.material) ==
                              entgfx::MaterialRenderQueue::Translucent;
  const bool depth_write = entgfx::materialWritesDepth(object.material) && !alpha_blend;

  for (std::size_t i = 0; i + 2u < mesh.indices.size(); i += 3u) {
    const ProjectedVertex a =
        projectVertex(mesh.vertices[mesh.indices[i + 0u]], model, model_view_projection,
                      framebuffer.width(), framebuffer.height());
    const ProjectedVertex b =
        projectVertex(mesh.vertices[mesh.indices[i + 1u]], model, model_view_projection,
                      framebuffer.width(), framebuffer.height());
    const ProjectedVertex c =
        projectVertex(mesh.vertices[mesh.indices[i + 2u]], model, model_view_projection,
                      framebuffer.width(), framebuffer.height());
    if (!a.valid || !b.valid || !c.valid ||
        shouldCullTriangle(a, b, c, camera_position, cull_mode)) {
      continue;
    }

    const entgfx::FrameVertex fa{
        .x = a.x,
        .y = a.y,
        .depth = a.depth,
        .color =
            shadedFrameColor(object.material, a.world_position, a.normal, a.uv, a.ambient_occlusion,
                             camera_position, settings, frame_seconds, opacity),
    };
    const entgfx::FrameVertex fb{
        .x = b.x,
        .y = b.y,
        .depth = b.depth,
        .color =
            shadedFrameColor(object.material, b.world_position, b.normal, b.uv, b.ambient_occlusion,
                             camera_position, settings, frame_seconds, opacity),
    };
    const entgfx::FrameVertex fc{
        .x = c.x,
        .y = c.y,
        .depth = c.depth,
        .color =
            shadedFrameColor(object.material, c.world_position, c.normal, c.uv, c.ambient_occlusion,
                             camera_position, settings, frame_seconds, opacity),
    };
    framebuffer.drawTriangle(fa, fb, fc, settings.pipeline.depth_test, depth_write, alpha_blend);
  }
  ++draw_calls;
}

} // namespace

namespace entgfx {

RenderDevice::RenderDevice() = default;
RenderDevice::~RenderDevice() = default;

const CpuMesh &RenderDevice::meshForPrimitive(const MeshPrimitive primitive) const {
  switch (primitive) {
  case MeshPrimitive::Box:
    return box_;
  case MeshPrimitive::Sphere:
    return sphere_;
  case MeshPrimitive::Plane:
    return plane_;
  case MeshPrimitive::Rock:
    return rock_;
  case MeshPrimitive::Crystal:
    return crystal_;
  case MeshPrimitive::RuinBlock:
    return ruin_block_;
  case MeshPrimitive::Pillar:
    return pillar_;
  }
  return sphere_;
}

const CpuMesh &RenderDevice::meshForObject(const RenderObject &object) {
  if (object.custom_mesh == nullptr) {
    return meshForPrimitive(object.primitive);
  }

  if (object.dynamic_mesh.valid()) {
    auto it = custom_mesh_resource_cache_.find(object.dynamic_mesh);
    if (it == custom_mesh_resource_cache_.end()) {
      it = custom_mesh_resource_cache_
               .emplace(object.dynamic_mesh,
                        prepareMeshForRendering(*object.custom_mesh, renderMeshOptions()))
               .first;
    }
    return it->second;
  }

  const CpuMesh *source = object.custom_mesh.get();
  auto it = custom_mesh_cache_.find(source);
  if (it == custom_mesh_cache_.end()) {
    it = custom_mesh_cache_.emplace(source, prepareMeshForRendering(*source, renderMeshOptions()))
             .first;
  }
  return it->second;
}

void RenderDevice::syncDynamicMeshes(const Scene &scene, const bool immediate_eviction) {
  ENTGFX_PROFILE_SCOPE("RenderDevice::syncDynamicMeshes");
  ++mesh_cache_frame_;
  std::unordered_set<const CpuMesh *> live_meshes;
  std::unordered_set<DynamicMeshResourceKey, DynamicMeshResourceKeyHash> live_resources;
  live_meshes.reserve(scene.objects().size());
  live_resources.reserve(scene.objects().size());
  for (const RenderObject &object : scene.objects()) {
    if (object.custom_mesh == nullptr) {
      continue;
    }
    if (object.dynamic_mesh.valid()) {
      live_resources.insert(object.dynamic_mesh);
      custom_mesh_resource_last_seen_[object.dynamic_mesh] = mesh_cache_frame_;
    } else {
      live_meshes.insert(object.custom_mesh.get());
      custom_mesh_last_seen_[object.custom_mesh.get()] = mesh_cache_frame_;
    }
  }

  constexpr std::uint64_t kRetiredMeshGraceFrames = 3u;
  for (auto it = custom_mesh_cache_.begin(); it != custom_mesh_cache_.end();) {
    const auto seen = custom_mesh_last_seen_.find(it->first);
    const bool live = live_meshes.contains(it->first);
    const bool expired =
        immediate_eviction || seen == custom_mesh_last_seen_.end() ||
        mesh_cache_frame_ > seen->second + kRetiredMeshGraceFrames;
    if (live || !expired) {
      ++it;
    } else {
      custom_mesh_last_seen_.erase(it->first);
      it = custom_mesh_cache_.erase(it);
    }
  }

  for (auto it = custom_mesh_resource_cache_.begin(); it != custom_mesh_resource_cache_.end();) {
    const auto seen = custom_mesh_resource_last_seen_.find(it->first);
    const bool live = live_resources.contains(it->first);
    const bool expired =
        immediate_eviction || seen == custom_mesh_resource_last_seen_.end() ||
        mesh_cache_frame_ > seen->second + kRetiredMeshGraceFrames;
    if (live || !expired) {
      ++it;
    } else {
      custom_mesh_resource_last_seen_.erase(it->first);
      it = custom_mesh_resource_cache_.erase(it);
    }
  }

  for (const CpuMesh *mesh : live_meshes) {
    if (!custom_mesh_cache_.contains(mesh)) {
      custom_mesh_cache_.emplace(mesh, prepareMeshForRendering(*mesh, renderMeshOptions()));
    }
  }
  for (const RenderObject &object : scene.objects()) {
    if (object.custom_mesh != nullptr && object.dynamic_mesh.valid() &&
        !custom_mesh_resource_cache_.contains(object.dynamic_mesh)) {
      custom_mesh_resource_cache_.emplace(
          object.dynamic_mesh, prepareMeshForRendering(*object.custom_mesh, renderMeshOptions()));
    }
  }
}

void RenderDevice::initialize() {
  ENTGFX_PROFILE_SCOPE("RenderDevice::initialize");
  const MeshProcessOptions mesh_options = renderMeshOptions();
  box_ = prepareMeshForRendering(makeBox(), mesh_options);
  sphere_ =
      prepareMeshForRendering(makeUvSphere(kSphereSegments, kSphereRings, 1.0f), mesh_options);
  plane_ = prepareMeshForRendering(makePlane(kPlaneSize), mesh_options);
  contact_shadow_plane_ = prepareMeshForRendering(makePlane(kContactShadowPlaneSize), mesh_options);
  rock_ = prepareMeshForRendering(makeRock(kRockSegments, kRockRings, 1.0f), mesh_options);
  crystal_ = prepareMeshForRendering(makeCrystal(kCrystalSides, 1.0f, 1.8f), mesh_options);
  ruin_block_ = prepareMeshForRendering(makeRuinBlock(), mesh_options);
  pillar_ = prepareMeshForRendering(makePillar(kPillarSides, 1.0f, 1.0f), mesh_options);

  const char *force_software = std::getenv("ENTGFX_FORCE_SOFTWARE_RENDERER");
  if (force_software == nullptr || *force_software == '\0') {
    native_backend_ = createNativeRenderBackend();
    if (native_backend_ != nullptr && !native_backend_->initialize()) {
      native_backend_.reset();
    }
  }
}

void RenderDevice::prepareScene(const Scene &scene) {
  ENTGFX_PROFILE_SCOPE("RenderDevice::prepareScene");
  render_scene_.rebuild(scene);
  syncDynamicMeshes(scene, true);
}

FrameStats RenderDevice::render(const Scene &scene, const OrbitCamera &camera,
                                const RendererSettings &settings, const int framebuffer_width,
                                const int framebuffer_height, const double frame_seconds) {
  ENTGFX_PROFILE_SCOPE("RenderDevice::render");
  FrameStats stats;
  stats.frame_seconds = frame_seconds;
  stats.framebuffer_width = framebuffer_width;
  stats.framebuffer_height = framebuffer_height;

  if (framebuffer_width <= 0 || framebuffer_height <= 0) {
    return stats;
  }

  syncDynamicMeshes(scene, false);
  render_scene_.rebuild(scene);
  const FrameRenderPlan plan =
      buildFrameRenderPlan(render_scene_, camera, settings.line_of_sight_fade, framebuffer_width,
                           framebuffer_height);
  stats.visible_objects = plan.diagnostics.visible_objects;
  stats.culled_objects = plan.diagnostics.culled_objects;
  stats.instance_groups = plan.diagnostics.instance_groups;
  stats.lod_culled_objects = plan.diagnostics.lod_culled_objects;
  stats.visibility_hint_objects = plan.diagnostics.visibility_hint_objects;
  stats.dynamic_mesh_objects = plan.diagnostics.dynamic_mesh_objects;
  stats.dynamic_mesh_cache_entries =
      custom_mesh_cache_.size() + custom_mesh_resource_cache_.size();
  stats.rust_plan_seconds = plan.diagnostics.rust_plan_seconds;

  SoftwareFrameBuffer &framebuffer = activeFrameBuffer();
  if (native_backend_ != nullptr) {
    PreparedRenderMeshes meshes{
        .box = &box_,
        .sphere = &sphere_,
        .plane = &plane_,
        .contact_shadow_plane = &contact_shadow_plane_,
        .rock = &rock_,
        .crystal = &crystal_,
        .ruin_block = &ruin_block_,
        .pillar = &pillar_,
        .custom_meshes = &custom_mesh_cache_,
        .custom_mesh_resources = &custom_mesh_resource_cache_,
    };
    framebuffer.resize(framebuffer_width, framebuffer_height);
    framebuffer.clearTransparent();
    FrameStats native_stats = native_backend_->render(scene, plan, camera, settings, meshes,
                                                      framebuffer_width, framebuffer_height,
                                                      frame_seconds);
    native_stats.visible_objects = plan.diagnostics.visible_objects;
    native_stats.culled_objects = plan.diagnostics.culled_objects;
    native_stats.instance_groups = plan.diagnostics.instance_groups;
    native_stats.lod_culled_objects = plan.diagnostics.lod_culled_objects;
    native_stats.visibility_hint_objects = plan.diagnostics.visibility_hint_objects;
    native_stats.dynamic_mesh_objects = plan.diagnostics.dynamic_mesh_objects;
    native_stats.dynamic_mesh_cache_entries =
        custom_mesh_cache_.size() + custom_mesh_resource_cache_.size();
    native_stats.rust_plan_seconds = plan.diagnostics.rust_plan_seconds;
    return native_stats;
  }

  clearNativeFrame();
  framebuffer.resize(framebuffer_width, framebuffer_height);
  framebuffer.clear(settings.pipeline.clear_color);

  const auto encode_start = std::chrono::steady_clock::now();

  const auto draw_object = [&](const RenderObject &object, const float opacity) {
    const CpuMesh &mesh = isContactShadowUtility(object) && object.custom_mesh == nullptr
                              ? contact_shadow_plane_
                              : meshForObject(object);
    drawMesh(framebuffer, mesh, object, camera, settings, frame_seconds, opacity, stats.draw_calls);
  };

  for (const FrameRenderDrawGroup &group : plan.groups) {
    if (group.pass != FrameRenderPass::Opaque) {
      continue;
    }
    for (std::size_t i = 0; i < group.instance_count; ++i) {
      const FrameRenderInstance &instance = plan.instances[group.first_instance + i];
      if (instance.object_index < scene.objects().size()) {
        draw_object(scene.objects()[instance.object_index], instance.opacity);
      }
    }
  }

  for (const FrameRenderInstance &instance : plan.instances) {
    if (instance.object_index >= scene.objects().size()) {
      continue;
    }
    const RenderObject &object = scene.objects()[instance.object_index];
    if (canCastContactShadow(object, settings.grounding)) {
      const RenderObject shadow = contactShadowObjectFor(object, settings.grounding);
      draw_object(shadow, shadow.material.opacity);
    }
  }

  for (const FrameRenderDrawGroup &group : plan.groups) {
    if (group.pass != FrameRenderPass::Transparent) {
      continue;
    }
    for (std::size_t i = 0; i < group.instance_count; ++i) {
      const FrameRenderInstance &instance = plan.instances[group.first_instance + i];
      if (instance.object_index < scene.objects().size()) {
        draw_object(scene.objects()[instance.object_index], instance.opacity);
      }
    }
  }
  const auto encode_end = std::chrono::steady_clock::now();
  stats.render_encode_seconds = std::chrono::duration<double>(encode_end - encode_start).count();

  return stats;
}

const char *RenderDevice::backendName() const {
  if (native_backend_ != nullptr) {
    return native_backend_->backendName();
  }
  return "EntGfx Learning Software Rentgfxizer";
}

} // namespace entgfx
