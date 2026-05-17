
use std::cmp::Ordering;
use std::slice;
use std::time::Instant;

const ENTGFX_RENDER_FLAG_FADE_ELIGIBLE: u32 = 1 << 0;
const ENTGFX_RENDER_QUEUE_TRANSLUCENT: u32 = 2;
const ENTGFX_RENDER_PASS_OPAQUE: u32 = 0;
const ENTGFX_RENDER_PASS_TRANSPARENT: u32 = 1;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct EntGfxRuntimeVec3 {
    pub x: f32,
    pub y: f32,
    pub z: f32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct EntGfxRuntimeRenderObject {
    pub entity_id: u64,
    pub object_index: u32,
    pub mesh_key: u64,
    pub material_key: u64,
    pub render_queue: u32,
    pub flags: u32,
    pub visibility_class: u32,
    pub position: EntGfxRuntimeVec3,
    pub visibility_cell: EntGfxRuntimeVec3,
    pub bounds_center: EntGfxRuntimeVec3,
    pub bounds_radius: f32,
    pub opacity: f32,
    pub lod_max_distance: f32,
    pub lod_min_projected_radius: f32,
    pub portal_depth: f32,
    pub dynamic_mesh_generation: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct EntGfxRuntimeCamera {
    pub position: EntGfxRuntimeVec3,
    pub forward: EntGfxRuntimeVec3,
    pub right: EntGfxRuntimeVec3,
    pub up: EntGfxRuntimeVec3,
    pub vertical_fov: f32,
    pub aspect_ratio: f32,
    pub near_plane: f32,
    pub far_plane: f32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct EntGfxRuntimeLineOfSightFade {
    pub enabled: u32,
    pub camera_position: EntGfxRuntimeVec3,
    pub target_position: EntGfxRuntimeVec3,
    pub radius: f32,
    pub min_opacity: f32,
    pub camera_clearance: f32,
    pub target_clearance: f32,
    pub max_object_radius: f32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct EntGfxRuntimeRenderPlanOptions {
    pub line_of_sight_fade: EntGfxRuntimeLineOfSightFade,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct EntGfxRuntimeDrawInstance {
    pub object_index: u32,
    pub opacity: f32,
    pub sort_distance_sq: f32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct EntGfxRuntimeDrawGroup {
    pub mesh_key: u64,
    pub material_key: u64,
    pub render_queue: u32,
    pub pass: u32,
    pub first_instance: usize,
    pub instance_count: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct EntGfxRuntimeRenderDiagnostics {
    pub object_count: usize,
    pub visible_objects: usize,
    pub culled_objects: usize,
    pub opaque_groups: usize,
    pub transparent_groups: usize,
    pub instance_groups: usize,
    pub planned_instances: usize,
    pub lod_culled_objects: usize,
    pub visibility_hint_objects: usize,
    pub dynamic_mesh_objects: usize,
    pub rust_plan_seconds: f64,
}

#[repr(C)]
#[derive(Debug)]
pub struct EntGfxRuntimeFramePlan {
    pub instances: *mut EntGfxRuntimeDrawInstance,
    pub instance_count: usize,
    pub groups: *mut EntGfxRuntimeDrawGroup,
    pub group_count: usize,
    pub diagnostics: EntGfxRuntimeRenderDiagnostics,
}

impl Default for EntGfxRuntimeFramePlan {
    fn default() -> Self {
        Self {
            instances: std::ptr::null_mut(),
            instance_count: 0,
            groups: std::ptr::null_mut(),
            group_count: 0,
            diagnostics: EntGfxRuntimeRenderDiagnostics::default(),
        }
    }
}

#[derive(Clone, Copy)]
struct PlannedObject {
    object: EntGfxRuntimeRenderObject,
    opacity: f32,
    sort_distance_sq: f32,
    transparent: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DrawKey {
    pub mesh_key: u64,
    pub material_key: u64,
    pub render_queue: u32,
    pub pass: u32,
}

#[derive(Clone, Debug, Default)]
pub struct PlannerSummary {
    pub object_count: usize,
    pub visible_objects: usize,
    pub culled_objects: usize,
    pub opaque_groups: usize,
    pub transparent_groups: usize,
    pub instance_groups: usize,
    pub planned_instances: usize,
    pub lod_culled_objects: usize,
    pub visibility_hint_objects: usize,
    pub dynamic_mesh_objects: usize,
}

#[derive(Clone, Debug, Default)]
pub struct PlannerOutput {
    pub instances: Vec<EntGfxRuntimeDrawInstance>,
    pub groups: Vec<EntGfxRuntimeDrawGroup>,
    pub summary: PlannerSummary,
}

fn dot(lhs: EntGfxRuntimeVec3, rhs: EntGfxRuntimeVec3) -> f32 {
    lhs.x * rhs.x + lhs.y * rhs.y + lhs.z * rhs.z
}

fn sub(lhs: EntGfxRuntimeVec3, rhs: EntGfxRuntimeVec3) -> EntGfxRuntimeVec3 {
    EntGfxRuntimeVec3 {
        x: lhs.x - rhs.x,
        y: lhs.y - rhs.y,
        z: lhs.z - rhs.z,
    }
}

fn length_sq(value: EntGfxRuntimeVec3) -> f32 {
    dot(value, value)
}

fn add(lhs: EntGfxRuntimeVec3, rhs: EntGfxRuntimeVec3) -> EntGfxRuntimeVec3 {
    EntGfxRuntimeVec3 {
        x: lhs.x + rhs.x,
        y: lhs.y + rhs.y,
        z: lhs.z + rhs.z,
    }
}

fn scale(value: EntGfxRuntimeVec3, scalar: f32) -> EntGfxRuntimeVec3 {
    EntGfxRuntimeVec3 {
        x: value.x * scalar,
        y: value.y * scalar,
        z: value.z * scalar,
    }
}

fn cross(lhs: EntGfxRuntimeVec3, rhs: EntGfxRuntimeVec3) -> EntGfxRuntimeVec3 {
    EntGfxRuntimeVec3 {
        x: lhs.y * rhs.z - lhs.z * rhs.y,
        y: lhs.z * rhs.x - lhs.x * rhs.z,
        z: lhs.x * rhs.y - lhs.y * rhs.x,
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct EntGfxRuntimeMeshCutMeasure {
    pub centroid: EntGfxRuntimeVec3,
    pub bounds_min: EntGfxRuntimeVec3,
    pub bounds_max: EntGfxRuntimeVec3,
    pub surface_area: f32,
    pub signed_volume: f32,
}

pub fn measure_mesh_cut(
    vertices: &[EntGfxRuntimeVec3],
    indices: &[u32],
) -> Option<EntGfxRuntimeMeshCutMeasure> {
    if vertices.is_empty() || indices.len() < 3 || indices.len() % 3 != 0 {
        return None;
    }

    let mut bounds_min = EntGfxRuntimeVec3 {
        x: f32::INFINITY,
        y: f32::INFINITY,
        z: f32::INFINITY,
    };
    let mut bounds_max = EntGfxRuntimeVec3 {
        x: f32::NEG_INFINITY,
        y: f32::NEG_INFINITY,
        z: f32::NEG_INFINITY,
    };
    for &vertex in vertices {
        bounds_min.x = bounds_min.x.min(vertex.x);
        bounds_min.y = bounds_min.y.min(vertex.y);
        bounds_min.z = bounds_min.z.min(vertex.z);
        bounds_max.x = bounds_max.x.max(vertex.x);
        bounds_max.y = bounds_max.y.max(vertex.y);
        bounds_max.z = bounds_max.z.max(vertex.z);
    }

    let mut area_centroid = EntGfxRuntimeVec3::default();
    let mut surface_area = 0.0f32;
    let mut signed_volume = 0.0f32;
    for triangle in indices.chunks_exact(3) {
        let ia = triangle[0] as usize;
        let ib = triangle[1] as usize;
        let ic = triangle[2] as usize;
        if ia >= vertices.len() || ib >= vertices.len() || ic >= vertices.len() {
            return None;
        }
        let a = vertices[ia];
        let b = vertices[ib];
        let c = vertices[ic];
        let area = length_sq(cross(sub(b, a), sub(c, a))).sqrt() * 0.5;
        if area > f32::EPSILON {
            area_centroid = add(area_centroid, scale(add(add(a, b), c), area / 3.0));
            surface_area += area;
        }
        signed_volume += dot(a, cross(b, c)) / 6.0;
    }

    if surface_area <= f32::EPSILON {
        return None;
    }

    Some(EntGfxRuntimeMeshCutMeasure {
        centroid: scale(area_centroid, 1.0 / surface_area),
        bounds_min,
        bounds_max,
        surface_area,
        signed_volume,
    })
}

fn distance_point_segment_sq(
    point: EntGfxRuntimeVec3,
    from: EntGfxRuntimeVec3,
    to: EntGfxRuntimeVec3,
) -> (f32, f32, f32) {
    let segment = sub(to, from);
    let denom = length_sq(segment);
    if denom <= f32::EPSILON {
        return (length_sq(sub(point, from)), 0.0, 0.0);
    }
    let segment_length = denom.sqrt();
    let t = (dot(sub(point, from), segment) / denom).clamp(0.0, 1.0);
    let closest = EntGfxRuntimeVec3 {
        x: from.x + segment.x * t,
        y: from.y + segment.y * t,
        z: from.z + segment.z * t,
    };
    (
        length_sq(sub(point, closest)),
        segment_length * t,
        segment_length,
    )
}

fn visible_to_camera(object: EntGfxRuntimeRenderObject, camera: EntGfxRuntimeCamera) -> bool {
    let radius = object.bounds_radius.max(0.0);
    let camera_to_object = sub(object.bounds_center, camera.position);
    let distance_sq = length_sq(camera_to_object);
    let far = camera.far_plane.max(camera.near_plane).max(0.0);
    if distance_sq > (far + radius) * (far + radius) {
        return false;
    }

    let forward_distance = dot(camera_to_object, camera.forward);
    if forward_distance < -radius || forward_distance > far + radius {
        return false;
    }

    let plane_distance = forward_distance.max(camera.near_plane.max(0.001));
    let vertical_limit = (camera.vertical_fov * 0.5).tan() * plane_distance + radius;
    let horizontal_limit = vertical_limit * camera.aspect_ratio.max(0.001) + radius;
    dot(camera_to_object, camera.right).abs() <= horizontal_limit
        && dot(camera_to_object, camera.up).abs() <= vertical_limit
}

fn passes_lod_policy(object: EntGfxRuntimeRenderObject, camera: EntGfxRuntimeCamera) -> bool {
    let radius = object.bounds_radius.max(0.0);
    let camera_to_object = sub(object.bounds_center, camera.position);
    let distance_sq = length_sq(camera_to_object);
    if object.lod_max_distance > 0.0 {
        let distance = distance_sq.sqrt();
        if distance - radius > object.lod_max_distance {
            return false;
        }
    }
    if object.lod_min_projected_radius > 0.0 {
        let forward_distance = dot(camera_to_object, camera.forward).max(camera.near_plane.max(0.001));
        let focal = 1.0 / (camera.vertical_fov * 0.5).tan().max(0.001);
        let projected_radius = radius * focal / forward_distance;
        if projected_radius < object.lod_min_projected_radius {
            return false;
        }
    }
    true
}

fn fade_opacity(
    object: EntGfxRuntimeRenderObject,
    options: EntGfxRuntimeRenderPlanOptions,
) -> Option<f32> {
    let fade = options.line_of_sight_fade;
    if fade.enabled == 0 || object.flags & ENTGFX_RENDER_FLAG_FADE_ELIGIBLE == 0 {
        return None;
    }
    let radius = object.bounds_radius.max(0.0);
    if fade.max_object_radius > 0.0 && radius > fade.max_object_radius {
        return None;
    }
    let limit = radius + fade.radius.max(0.0);
    let (distance_sq, along, segment_length) = distance_point_segment_sq(
        object.bounds_center,
        fade.camera_position,
        fade.target_position,
    );
    if segment_length <= 0.001
        || along <= fade.camera_clearance.max(0.0)
        || along >= segment_length - fade.target_clearance.max(0.0)
    {
        return None;
    }
    if distance_sq > limit * limit {
        return None;
    }
    Some(object.opacity.min(fade.min_opacity.clamp(0.0, 1.0)))
}

fn object_key(object: EntGfxRuntimeRenderObject, pass: u32) -> DrawKey {
    DrawKey {
        mesh_key: object.mesh_key,
        material_key: object.material_key,
        render_queue: object.render_queue,
        pass,
    }
}

fn append_groups(
    planned: &[PlannedObject],
    pass: u32,
    instances: &mut Vec<EntGfxRuntimeDrawInstance>,
    groups: &mut Vec<EntGfxRuntimeDrawGroup>,
) -> usize {
    let first_group = groups.len();
    let mut cursor = 0;
    while cursor < planned.len() {
        let key = object_key(planned[cursor].object, pass);
        let first_instance = instances.len();
        let mut count = 0;
        while cursor + count < planned.len()
            && object_key(planned[cursor + count].object, pass) == key
        {
            let item = planned[cursor + count];
            instances.push(EntGfxRuntimeDrawInstance {
                object_index: item.object.object_index,
                opacity: item.opacity,
                sort_distance_sq: item.sort_distance_sq,
                flags: if item.opacity < item.object.opacity {
                    ENTGFX_RENDER_FLAG_FADE_ELIGIBLE
                } else {
                    0
                },
            });
            count += 1;
        }
        groups.push(EntGfxRuntimeDrawGroup {
            mesh_key: key.mesh_key,
            material_key: key.material_key,
            render_queue: key.render_queue,
            pass: key.pass,
            first_instance,
            instance_count: count,
        });
        cursor += count;
    }
    groups.len() - first_group
}

pub fn build_frame_plan(
    objects: &[EntGfxRuntimeRenderObject],
    camera: EntGfxRuntimeCamera,
    options: EntGfxRuntimeRenderPlanOptions,
) -> PlannerOutput {
    let mut opaque = Vec::new();
    let mut transparent = Vec::new();
    let mut lod_culled_objects = 0usize;
    let mut visibility_hint_objects = 0usize;
    let mut dynamic_mesh_objects = 0usize;

    for &object in objects {
        if object.visibility_class != 0 {
            visibility_hint_objects += 1;
        }
        if object.dynamic_mesh_generation != 0 {
            dynamic_mesh_objects += 1;
        }
        if !visible_to_camera(object, camera) {
            continue;
        }
        if !passes_lod_policy(object, camera) {
            lod_culled_objects += 1;
            continue;
        }
        let camera_delta = sub(object.bounds_center, camera.position);
        let sort_distance_sq = length_sq(camera_delta);
        let fade_opacity = fade_opacity(object, options);
        let transparent_object =
            object.render_queue == ENTGFX_RENDER_QUEUE_TRANSLUCENT || fade_opacity.is_some();
        let planned = PlannedObject {
            object,
            opacity: fade_opacity.unwrap_or(object.opacity),
            sort_distance_sq,
            transparent: transparent_object,
        };
        if planned.transparent {
            transparent.push(planned);
        } else {
            opaque.push(planned);
        }
    }

    opaque.sort_by(|lhs, rhs| {
        object_key(lhs.object, ENTGFX_RENDER_PASS_OPAQUE)
            .mesh_key
            .cmp(&object_key(rhs.object, ENTGFX_RENDER_PASS_OPAQUE).mesh_key)
            .then_with(|| lhs.object.material_key.cmp(&rhs.object.material_key))
            .then_with(|| lhs.object.render_queue.cmp(&rhs.object.render_queue))
            .then_with(|| lhs.object.object_index.cmp(&rhs.object.object_index))
    });
    transparent.sort_by(|lhs, rhs| {
        rhs.sort_distance_sq
            .partial_cmp(&lhs.sort_distance_sq)
            .unwrap_or(Ordering::Equal)
            .then_with(|| lhs.object.object_index.cmp(&rhs.object.object_index))
    });

    let visible_objects = opaque.len() + transparent.len();
    let mut instances = Vec::with_capacity(visible_objects);
    let mut groups = Vec::new();
    let opaque_groups = append_groups(
        &opaque,
        ENTGFX_RENDER_PASS_OPAQUE,
        &mut instances,
        &mut groups,
    );
    let transparent_groups = append_groups(
        &transparent,
        ENTGFX_RENDER_PASS_TRANSPARENT,
        &mut instances,
        &mut groups,
    );

    PlannerOutput {
        summary: PlannerSummary {
            object_count: objects.len(),
            visible_objects,
            culled_objects: objects.len().saturating_sub(visible_objects),
            opaque_groups,
            transparent_groups,
            instance_groups: groups.len(),
            planned_instances: instances.len(),
            lod_culled_objects,
            visibility_hint_objects,
            dynamic_mesh_objects,
        },
        instances,
        groups,
    }
}

#[no_mangle]
pub extern "C" fn entgfx_runtime_build_frame_plan(
    objects: *const EntGfxRuntimeRenderObject,
    object_count: usize,
    camera: EntGfxRuntimeCamera,
    options: EntGfxRuntimeRenderPlanOptions,
    out_plan: *mut EntGfxRuntimeFramePlan,
) -> u32 {
    let started = Instant::now();
    if out_plan.is_null() {
        return 0;
    }
    if objects.is_null() && object_count > 0 {
        unsafe {
            *out_plan = EntGfxRuntimeFramePlan::default();
        }
        return 0;
    }
    let object_slice = if object_count == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(objects, object_count) }
    };
    let output = build_frame_plan(object_slice, camera, options);

    let mut instances = output.instances.into_boxed_slice();
    let mut groups = output.groups.into_boxed_slice();
    let instance_count = instances.len();
    let group_count = groups.len();
    let instance_ptr = instances.as_mut_ptr();
    let group_ptr = groups.as_mut_ptr();
    std::mem::forget(instances);
    std::mem::forget(groups);

    unsafe {
        *out_plan = EntGfxRuntimeFramePlan {
            instances: instance_ptr,
            instance_count,
            groups: group_ptr,
            group_count,
            diagnostics: EntGfxRuntimeRenderDiagnostics {
                object_count: output.summary.object_count,
                visible_objects: output.summary.visible_objects,
                culled_objects: output.summary.culled_objects,
                opaque_groups: output.summary.opaque_groups,
                transparent_groups: output.summary.transparent_groups,
                instance_groups: output.summary.instance_groups,
                planned_instances: output.summary.planned_instances,
                lod_culled_objects: output.summary.lod_culled_objects,
                visibility_hint_objects: output.summary.visibility_hint_objects,
                dynamic_mesh_objects: output.summary.dynamic_mesh_objects,
                rust_plan_seconds: started.elapsed().as_secs_f64(),
            },
        };
    }
    1
}

#[no_mangle]
pub extern "C" fn entgfx_runtime_free_frame_plan(plan: EntGfxRuntimeFramePlan) {
    if !plan.instances.is_null() && plan.instance_count > 0 {
        unsafe {
            drop(Vec::from_raw_parts(
                plan.instances,
                plan.instance_count,
                plan.instance_count,
            ));
        }
    }
    if !plan.groups.is_null() && plan.group_count > 0 {
        unsafe {
            drop(Vec::from_raw_parts(
                plan.groups,
                plan.group_count,
                plan.group_count,
            ));
        }
    }
}

#[no_mangle]
pub extern "C" fn entgfx_runtime_measure_mesh_cut(
    vertices: *const EntGfxRuntimeVec3,
    vertex_count: usize,
    indices: *const u32,
    index_count: usize,
    out_measure: *mut EntGfxRuntimeMeshCutMeasure,
) -> u32 {
    if out_measure.is_null()
        || (vertices.is_null() && vertex_count > 0)
        || (indices.is_null() && index_count > 0)
    {
        return 0;
    }

    let vertex_slice = if vertex_count == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(vertices, vertex_count) }
    };
    let index_slice = if index_count == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(indices, index_count) }
    };
    let Some(measure) = measure_mesh_cut(vertex_slice, index_slice) else {
        unsafe {
            *out_measure = EntGfxRuntimeMeshCutMeasure::default();
        }
        return 0;
    };

    unsafe {
        *out_measure = measure;
    }
    1
}

pub mod software_rentgfx {
    #[derive(Clone, Copy, Debug, Default)]
    pub struct RentgfxVertex {
        pub x: f32,
        pub y: f32,
        pub z: f32,
        pub rgba: [f32; 4],
    }

    #[derive(Clone, Debug)]
    pub struct RentgfxImage {
        pub width: usize,
        pub height: usize,
        pub color: Vec<[f32; 4]>,
        pub depth: Vec<f32>,
    }

    impl RentgfxImage {
        pub fn new(width: usize, height: usize) -> Self {
            let pixels = width.saturating_mul(height);
            Self {
                width,
                height,
                color: vec![[0.0, 0.0, 0.0, 0.0]; pixels],
                depth: vec![f32::INFINITY; pixels],
            }
        }

        pub fn clear(&mut self, rgba: [f32; 4]) {
            self.color.fill(rgba);
            self.depth.fill(f32::INFINITY);
        }

        pub fn pixel(&self, x: usize, y: usize) -> Option<[f32; 4]> {
            if x >= self.width || y >= self.height {
                return None;
            }
            self.color.get(y * self.width + x).copied()
        }
    }

    fn edge(a: RentgfxVertex, b: RentgfxVertex, x: f32, y: f32) -> f32 {
        (x - a.x) * (b.y - a.y) - (y - a.y) * (b.x - a.x)
    }

    fn lerp4(a: [f32; 4], b: [f32; 4], c: [f32; 4], wa: f32, wb: f32, wc: f32) -> [f32; 4] {
        [
            a[0] * wa + b[0] * wb + c[0] * wc,
            a[1] * wa + b[1] * wb + c[1] * wc,
            a[2] * wa + b[2] * wb + c[2] * wc,
            a[3] * wa + b[3] * wb + c[3] * wc,
        ]
    }

    pub fn rentgfxize_triangle(
        target: &mut RentgfxImage,
        a: RentgfxVertex,
        b: RentgfxVertex,
        c: RentgfxVertex,
    ) -> usize {
        if target.width == 0 || target.height == 0 {
            return 0;
        }
        let area = edge(a, b, c.x, c.y);
        if area.abs() <= f32::EPSILON {
            return 0;
        }
        let min_x = a.x.min(b.x).min(c.x).floor().max(0.0) as usize;
        let min_y = a.y.min(b.y).min(c.y).floor().max(0.0) as usize;
        let max_x =
            a.x.max(b.x)
                .max(c.x)
                .ceil()
                .min((target.width.saturating_sub(1)) as f32) as usize;
        let max_y =
            a.y.max(b.y)
                .max(c.y)
                .ceil()
                .min((target.height.saturating_sub(1)) as f32) as usize;
        let inv_area = 1.0 / area;
        let mut written = 0usize;
        for y in min_y..=max_y {
            for x in min_x..=max_x {
                let px = x as f32 + 0.5;
                let py = y as f32 + 0.5;
                let wa = edge(b, c, px, py) * inv_area;
                let wb = edge(c, a, px, py) * inv_area;
                let wc = edge(a, b, px, py) * inv_area;
                if wa < -0.00001 || wb < -0.00001 || wc < -0.00001 {
                    continue;
                }
                let depth = a.z * wa + b.z * wb + c.z * wc;
                let index = y * target.width + x;
                if depth >= target.depth[index] {
                    continue;
                }
                target.depth[index] = depth;
                target.color[index] = lerp4(a.rgba, b.rgba, c.rgba, wa, wb, wc);
                written += 1;
            }
        }
        written
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(
        index: u32,
        x: f32,
        mesh: u64,
        material: u64,
        queue: u32,
    ) -> EntGfxRuntimeRenderObject {
        EntGfxRuntimeRenderObject {
            entity_id: index as u64 + 1,
            object_index: index,
            mesh_key: mesh,
            material_key: material,
            render_queue: queue,
            flags: ENTGFX_RENDER_FLAG_FADE_ELIGIBLE,
            visibility_class: 0,
            position: EntGfxRuntimeVec3 { x, y: 0.0, z: 6.0 },
            visibility_cell: EntGfxRuntimeVec3::default(),
            bounds_center: EntGfxRuntimeVec3 { x, y: 0.0, z: 6.0 },
            bounds_radius: 0.5,
            opacity: 1.0,
            lod_max_distance: 0.0,
            lod_min_projected_radius: 0.0,
            portal_depth: 0.0,
            dynamic_mesh_generation: 0,
        }
    }

    fn camera() -> EntGfxRuntimeCamera {
        EntGfxRuntimeCamera {
            position: EntGfxRuntimeVec3::default(),
            forward: EntGfxRuntimeVec3 {
                x: 0.0,
                y: 0.0,
                z: 1.0,
            },
            right: EntGfxRuntimeVec3 {
                x: 1.0,
                y: 0.0,
                z: 0.0,
            },
            up: EntGfxRuntimeVec3 {
                x: 0.0,
                y: 1.0,
                z: 0.0,
            },
            vertical_fov: std::f32::consts::FRAC_PI_2,
            aspect_ratio: 1.0,
            near_plane: 0.01,
            far_plane: 20.0,
        }
    }

    #[test]
    fn groups_opaque_objects_by_draw_key() {
        let objects = [
            object(0, 0.0, 2, 7, 0),
            object(1, 0.3, 2, 7, 0),
            object(2, 0.6, 3, 7, 0),
        ];
        let output = build_frame_plan(&objects, camera(), EntGfxRuntimeRenderPlanOptions::default());
        assert_eq!(output.summary.visible_objects, 3);
        assert_eq!(output.summary.opaque_groups, 2);
        assert_eq!(output.groups[0].instance_count, 2);
        assert_eq!(output.groups[1].instance_count, 1);
    }

    #[test]
    fn culls_objects_outside_frustum() {
        let objects = [object(0, 0.0, 2, 7, 0), object(1, 100.0, 2, 7, 0)];
        let output = build_frame_plan(&objects, camera(), EntGfxRuntimeRenderPlanOptions::default());
        assert_eq!(output.summary.visible_objects, 1);
        assert_eq!(output.summary.culled_objects, 1);
    }

    #[test]
    fn reports_lod_visibility_and_dynamic_mesh_diagnostics() {
        let mut visible_dynamic = object(0, 0.0, 42, 7, 0);
        visible_dynamic.visibility_class = 3;
        visible_dynamic.dynamic_mesh_generation = 9;

        let mut lod_culled = object(1, 0.0, 43, 7, 0);
        lod_culled.lod_max_distance = 1.0;

        let output = build_frame_plan(
            &[visible_dynamic, lod_culled],
            camera(),
            EntGfxRuntimeRenderPlanOptions::default(),
        );
        assert_eq!(output.summary.visible_objects, 1);
        assert_eq!(output.summary.culled_objects, 1);
        assert_eq!(output.summary.lod_culled_objects, 1);
        assert_eq!(output.summary.visibility_hint_objects, 1);
        assert_eq!(output.summary.dynamic_mesh_objects, 1);
    }

    #[test]
    fn measures_cut_mesh_surface_and_bounds() {
        let vertices = [
            EntGfxRuntimeVec3 {
                x: 0.0,
                y: 0.0,
                z: 0.0,
            },
            EntGfxRuntimeVec3 {
                x: 1.0,
                y: 0.0,
                z: 0.0,
            },
            EntGfxRuntimeVec3 {
                x: 0.0,
                y: 1.0,
                z: 0.0,
            },
        ];
        let indices = [0u32, 1, 2];
        let measure = measure_mesh_cut(&vertices, &indices).expect("valid triangle");
        assert!((measure.surface_area - 0.5).abs() < 0.0001);
        assert!((measure.centroid.x - 1.0 / 3.0).abs() < 0.0001);
        assert!((measure.centroid.y - 1.0 / 3.0).abs() < 0.0001);
        assert_eq!(measure.bounds_max.x, 1.0);
        assert_eq!(measure.bounds_max.y, 1.0);
    }

    #[test]
    fn transparent_objects_sort_back_to_front() {
        let near = object(0, 0.0, 2, 7, ENTGFX_RENDER_QUEUE_TRANSLUCENT);
        let mut far = object(1, 0.0, 2, 7, ENTGFX_RENDER_QUEUE_TRANSLUCENT);
        far.position.z = 10.0;
        far.bounds_center.z = 10.0;
        let output = build_frame_plan(
            &[near, far],
            camera(),
            EntGfxRuntimeRenderPlanOptions::default(),
        );
        assert_eq!(output.instances[0].object_index, 1);
        assert_eq!(output.instances[1].object_index, 0);
    }

    #[test]
    fn software_rentgfx_depth_tests_triangles() {
        let mut image = software_rentgfx::RentgfxImage::new(8, 8);
        let far = [
            software_rentgfx::RentgfxVertex {
                x: 1.0,
                y: 1.0,
                z: 0.8,
                rgba: [0.0, 0.0, 1.0, 1.0],
            },
            software_rentgfx::RentgfxVertex {
                x: 6.0,
                y: 1.0,
                z: 0.8,
                rgba: [0.0, 0.0, 1.0, 1.0],
            },
            software_rentgfx::RentgfxVertex {
                x: 1.0,
                y: 6.0,
                z: 0.8,
                rgba: [0.0, 0.0, 1.0, 1.0],
            },
        ];
        let near = [
            software_rentgfx::RentgfxVertex {
                z: 0.2,
                rgba: [1.0, 0.0, 0.0, 1.0],
                ..far[0]
            },
            software_rentgfx::RentgfxVertex {
                z: 0.2,
                rgba: [1.0, 0.0, 0.0, 1.0],
                ..far[1]
            },
            software_rentgfx::RentgfxVertex {
                z: 0.2,
                rgba: [1.0, 0.0, 0.0, 1.0],
                ..far[2]
            },
        ];
        assert!(software_rentgfx::rentgfxize_triangle(&mut image, far[0], far[1], far[2]) > 0);
        assert!(software_rentgfx::rentgfxize_triangle(&mut image, near[0], near[1], near[2]) > 0);
        let pixel = image.pixel(2, 2).expect("covered pixel");
        assert!(pixel[0] > 0.9);
        assert!(pixel[2] < 0.1);
    }
}
