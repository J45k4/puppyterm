use std::{
    env,
    error::Error,
    fs::{self, File},
    path::PathBuf,
};

#[cfg(windows)]
fn main() -> Result<(), Box<dyn Error>> {
    use image::{
        ExtendedColorType, ImageFormat, codecs::ico::{IcoEncoder, IcoFrame}, imageops::FilterType,
    };

    println!("cargo:rerun-if-changed=assets/puppyterm.png");

    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let png_path = PathBuf::from("assets").join("puppyterm.png");
    let png_bytes = fs::read(&png_path)?;
    let base_image = image::load_from_memory_with_format(&png_bytes, ImageFormat::Png)?.into_rgba8();

    let mut frames = Vec::new();
    for size in [16_u32, 24, 32, 48, 64, 128, 256] {
        let resized =
            image::imageops::resize(&base_image, size, size, FilterType::Lanczos3).into_raw();
        frames.push(IcoFrame::as_png(
            &resized,
            size,
            size,
            ExtendedColorType::Rgba8,
        )?);
    }

    let icon_path = out_dir.join("puppyterm.ico");
    let icon_file = File::create(&icon_path)?;
    IcoEncoder::new(icon_file).encode_images(&frames)?;

    let rc_path = out_dir.join("puppyterm.rc");
    let icon_path_for_rc = icon_path.display().to_string().replace('\\', "/");
    fs::write(&rc_path, format!("APP_ICON ICON \"{icon_path_for_rc}\"\n"))?;

    embed_resource::compile(rc_path, embed_resource::NONE)
        .manifest_optional()
        .unwrap();

    Ok(())
}

#[cfg(not(windows))]
fn main() {
    println!("cargo:rerun-if-changed=assets/puppyterm.png");
    let _ = env::var("OUT_DIR");
}
