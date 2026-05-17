use anyhow::Result;
use ent_graphics::{render_source, RenderOptions, RenderReport};

pub fn render_native_source(source: &str, options: RenderOptions) -> Result<RenderReport> {
    render_source(source, options)
}
