//! Image shrinking shared by the web proxy and WhatsApp media delivery: JPEG, PNG and still WebP are
//! decoded, downscaled to `max_dim` and re-encoded as lossy WebP (or JPEG for clients that don't accept
//! WebP). Animations, GIF, SVG and AVIF are left alone. Results are kept only when smaller.
//! CPU-heavy work must run via `shrink_async` (blocking pool + semaphore).

use anyhow::{Result, anyhow, bail};
use image::codecs::jpeg::JpegEncoder;
use image::codecs::png::PngDecoder;
use image::codecs::webp::WebPDecoder;
use image::{ImageFormat, ImageReader};
use std::io::Cursor;
use std::sync::OnceLock;
use tokio::sync::Semaphore;

pub const JPEG: &str = "image/jpeg";
pub const WEBP: &str = "image/webp";
/// Refuse images whose decoded size would exceed this many pixels (decompression bombs).
const MAX_PIXELS: u64 = 40_000_000;
/// WebP's maximum width/height.
const WEBP_MAX_DIM: u32 = 16383;

/// Re-encodes `input` at `quality`, shrunk to fit `max_dim` (0 = keep size), as WebP if `webp_ok`
/// (else only JPEG → JPEG). Returns the new bytes and their MIME type, or None if not smaller / not handled.
pub fn shrink(input: &[u8], max_dim: u32, quality: u8, webp_ok: bool) -> Result<Option<(Vec<u8>, &'static str)>> {
    let fmt = image::guess_format(input)?;
    match fmt {
        ImageFormat::Jpeg => {}
        ImageFormat::Png if webp_ok => {
            if PngDecoder::new(Cursor::new(input))?.is_apng()? {
                return Ok(None);
            }
        }
        ImageFormat::WebP if webp_ok => {
            if WebPDecoder::new(Cursor::new(input))?.has_animation() {
                return Ok(None);
            }
        }
        _ => return Ok(None),
    }
    let (w, h) = ImageReader::with_format(Cursor::new(input), fmt).into_dimensions()?;
    if w as u64 * h as u64 > MAX_PIXELS {
        bail!("image too large: {w}x{h}");
    }
    let mut img = image::load_from_memory_with_format(input, fmt)?;
    if max_dim > 0 && (img.width() > max_dim || img.height() > max_dim) {
        img = img.thumbnail(max_dim, max_dim);
    }
    let (w, h, q) = (img.width(), img.height(), quality.clamp(1, 100));
    let (out, mime) = if webp_ok && w <= WEBP_MAX_DIM && h <= WEBP_MAX_DIM {
        let rgba = img.to_rgba8();
        let mem = if img.color().has_alpha() && rgba.pixels().any(|p| p[3] < 255) {
            webp::Encoder::from_rgba(&rgba, w, h).encode_simple(false, q as f32)
        } else {
            let rgb = img.to_rgb8();
            webp::Encoder::from_rgb(&rgb, w, h).encode_simple(false, q as f32)
        };
        (mem.map_err(|e| anyhow!("webp encoding: {e:?}"))?.to_vec(), WEBP)
    } else if fmt == ImageFormat::Jpeg {
        let mut out = Vec::new();
        JpegEncoder::new_with_quality(&mut out, q).encode_image(&img.to_rgb8())?;
        (out, JPEG)
    } else {
        return Ok(None);
    };
    Ok((out.len() < input.len()).then_some((out, mime)))
}

fn limiter() -> &'static Semaphore {
    static S: OnceLock<Semaphore> = OnceLock::new();
    S.get_or_init(|| Semaphore::new(std::thread::available_parallelism().map_or(2, |n| n.get())))
}

/// Async wrapper: bounded concurrency, runs on the blocking pool.
pub async fn shrink_async(input: Vec<u8>, max_dim: u32, quality: u8, webp_ok: bool) -> Result<Option<(Vec<u8>, &'static str)>> {
    let _permit = limiter().acquire().await?;
    tokio::task::spawn_blocking(move || shrink(&input, max_dim, quality, webp_ok)).await?
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use image::ImageEncoder;

    fn photo(w: u32, h: u32) -> image::RgbImage {
        image::RgbImage::from_fn(w, h, |x, y| {
            let n = (x.wrapping_mul(7919) ^ y.wrapping_mul(104729)) % 64;
            image::Rgb([((x / 4) as u8).wrapping_add(n as u8), (y / 3) as u8, ((x + y) / 6) as u8])
        })
    }

    /// A noisy 800x600 test photo at JPEG quality 95.
    pub fn sample_jpeg() -> Vec<u8> {
        let mut out = Vec::new();
        JpegEncoder::new_with_quality(&mut out, 95).encode_image(&photo(800, 600)).unwrap();
        out
    }

    /// The same photo as PNG, optionally with a transparent band.
    pub fn sample_png(alpha: bool) -> Vec<u8> {
        let mut out = Vec::new();
        let enc = image::codecs::png::PngEncoder::new(&mut out);
        if alpha {
            let src = photo(800, 600);
            let img = image::RgbaImage::from_fn(800, 600, |x, y| {
                let p = src.get_pixel(x, y).0;
                image::Rgba([p[0], p[1], p[2], if y < 100 { 0 } else { 255 }])
            });
            enc.write_image(&img, 800, 600, image::ExtendedColorType::Rgba8).unwrap();
        } else {
            enc.write_image(&photo(800, 600), 800, 600, image::ExtendedColorType::Rgb8).unwrap();
        }
        out
    }

    /// The same photo as a high-quality (large) still WebP.
    pub fn sample_webp() -> Vec<u8> {
        webp::Encoder::from_rgb(&photo(800, 600), 800, 600).encode_simple(false, 95.0).unwrap().to_vec()
    }

    fn decode(b: &[u8]) -> (ImageFormat, image::DynamicImage) {
        (image::guess_format(b).unwrap(), image::load_from_memory(b).unwrap())
    }

    #[test]
    fn everything_becomes_smaller_webp() {
        for (name, src) in [("jpeg", sample_jpeg()), ("png", sample_png(false)), ("png+alpha", sample_png(true)), ("webp", sample_webp())] {
            let (out, mime) = shrink(&src, 400, 40, true).unwrap().unwrap_or_else(|| panic!("{name} not shrunk"));
            assert_eq!(mime, WEBP);
            assert!(out.len() < src.len(), "{name}");
            let (fmt, img) = decode(&out);
            assert_eq!(fmt, ImageFormat::WebP);
            assert_eq!((img.width(), img.height()), (400, 300), "{name}");
            assert_eq!(img.color().has_alpha(), name == "png+alpha", "{name}");
        }
    }

    #[test]
    fn jpeg_only_clients_and_refusals() {
        // a client that doesn't accept WebP gets JPEG, and only for JPEG input
        let (out, mime) = shrink(&sample_jpeg(), 400, 40, false).unwrap().unwrap();
        assert_eq!((mime, decode(&out).0), (JPEG, ImageFormat::Jpeg));
        assert!(shrink(&sample_png(false), 400, 40, false).unwrap().is_none());
        // not smaller → refused; unknown formats → error or untouched
        assert!(shrink(&out, 0, 100, false).unwrap().is_none());
        assert!(shrink(b"not an image", 0, 50, true).is_err());
        assert!(shrink(b"GIF89a\x01\x00\x01\x00\x00\x00\x00;", 0, 50, true).unwrap().is_none());
    }

    /// An animated WebP (one frame, built by hand: VP8X + ANIM + ANMF around a still frame).
    fn animated_webp() -> Vec<u8> {
        let still = webp::Encoder::from_rgb(&photo(64, 48), 64, 48).encode_simple(false, 95.0).unwrap().to_vec();
        let frame = &still[12..]; // the "VP8 " chunk after "RIFF....WEBP"
        let le24 = |v: u32| v.to_le_bytes()[..3].to_vec();
        let chunk = |tag: &[u8], body: Vec<u8>| {
            let mut c = tag.to_vec();
            c.extend_from_slice(&(body.len() as u32).to_le_bytes());
            let pad = body.len() % 2;
            c.extend(body);
            c.extend(std::iter::repeat_n(0, pad));
            c
        };
        let vp8x = [vec![0x02, 0, 0, 0], le24(63), le24(47)].concat(); // animation flag
        let anim = vec![0, 0, 0, 0, 0, 0];
        let anmf = [le24(0), le24(0), le24(63), le24(47), le24(100), vec![0], frame.to_vec()].concat();
        let body = [b"WEBP".to_vec(), chunk(b"VP8X", vp8x), chunk(b"ANIM", anim), chunk(b"ANMF", anmf)].concat();
        [b"RIFF".to_vec(), (body.len() as u32).to_le_bytes().to_vec(), body].concat()
    }

    #[test]
    fn animations_are_left_alone() {
        let a = animated_webp();
        assert!(WebPDecoder::new(Cursor::new(&a[..])).unwrap().has_animation());
        assert!(shrink(&a, 10, 10, true).unwrap().is_none());
    }
}
