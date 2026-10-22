use std::io::Cursor;

use bytes::Bytes;
use image::{
    codecs::{jpeg::JpegEncoder, webp::WebPEncoder},
    DynamicImage, ExtendedColorType, GenericImageView, ImageFormat, ImageReader, Limits,
};

use crate::config::CompressionPreset;

const MIN_IMAGE_BYTES: usize = 32 * 1024;
const MAX_IMAGE_BYTES: usize = 8 * 1024 * 1024;
const MAX_DIMENSION: u32 = 8_192;
const MAX_PIXELS: u64 = 12_000_000;
const MAX_DECODE_ALLOC: u64 = 64 * 1024 * 1024;
const MIN_SAVING_BYTES: usize = 8 * 1024;

pub struct TransformedImage {
    pub body: Bytes,
    pub content_type: &'static str,
    pub saved_bytes: u64,
}

pub fn transform_image(
    body: &[u8],
    content_type: &str,
    accepts_webp: bool,
    preset: CompressionPreset,
) -> Option<TransformedImage> {
    if !(MIN_IMAGE_BYTES..=MAX_IMAGE_BYTES).contains(&body.len()) {
        return None;
    }
    match content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "image/jpeg" | "image/jpg" => transform_jpeg(body, preset),
        "image/png" if accepts_webp => transform_png(body),
        _ => None,
    }
}

fn transform_jpeg(body: &[u8], preset: CompressionPreset) -> Option<TransformedImage> {
    let quality = preset.jpeg_quality()?;
    if !jpeg_is_safe_to_transform(body) {
        return None;
    }
    let image = decode_bounded(body, ImageFormat::Jpeg)?;
    let mut output = Vec::with_capacity(body.len());
    JpegEncoder::new_with_quality(&mut output, quality)
        .encode_image(&DynamicImage::ImageRgb8(image.to_rgb8()))
        .ok()?;
    worthwhile(body.len(), output.len()).then(|| TransformedImage {
        saved_bytes: body.len().saturating_sub(output.len()) as u64,
        body: Bytes::from(output),
        content_type: "image/jpeg",
    })
}

fn transform_png(body: &[u8]) -> Option<TransformedImage> {
    if !png_is_safe_to_transform(body) {
        return None;
    }
    let image = decode_bounded(body, ImageFormat::Png)?;
    let rgba = image.to_rgba8();
    let (width, height) = image.dimensions();
    let mut output = Vec::with_capacity(body.len());
    WebPEncoder::new_lossless(&mut output)
        .encode(&rgba, width, height, ExtendedColorType::Rgba8)
        .ok()?;
    worthwhile(body.len(), output.len()).then(|| TransformedImage {
        saved_bytes: body.len().saturating_sub(output.len()) as u64,
        body: Bytes::from(output),
        content_type: "image/webp",
    })
}

fn decode_bounded(body: &[u8], format: ImageFormat) -> Option<DynamicImage> {
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_DIMENSION);
    limits.max_image_height = Some(MAX_DIMENSION);
    limits.max_alloc = Some(MAX_DECODE_ALLOC);

    let mut dimensions_reader = ImageReader::with_format(Cursor::new(body), format);
    dimensions_reader.limits(limits.clone());
    let dimensions = dimensions_reader.into_dimensions().ok()?;
    if !dimensions_within_limits(dimensions.0, dimensions.1) {
        return None;
    }

    let mut reader = ImageReader::with_format(Cursor::new(body), format);
    reader.limits(limits);
    reader.decode().ok()
}

fn worthwhile(original: usize, transformed: usize) -> bool {
    transformed < original
        && original.saturating_sub(transformed) >= MIN_SAVING_BYTES
        && transformed.saturating_mul(100) <= original.saturating_mul(90)
}

fn dimensions_within_limits(width: u32, height: u32) -> bool {
    width != 0
        && height != 0
        && width <= MAX_DIMENSION
        && height <= MAX_DIMENSION
        && u64::from(width) * u64::from(height) <= MAX_PIXELS
}

fn jpeg_is_safe_to_transform(body: &[u8]) -> bool {
    if !body.starts_with(b"\xff\xd8") {
        return false;
    }

    let mut offset = 2;
    let mut saw_frame = false;
    let mut saw_jfif = false;
    while offset < body.len() {
        if body[offset] != 0xff {
            return false;
        }
        while body.get(offset) == Some(&0xff) {
            offset += 1;
        }
        let Some(&marker) = body.get(offset) else {
            return false;
        };
        offset += 1;

        match marker {
            0xc0 => {
                let Some((payload, next)) = jpeg_segment(body, offset) else {
                    return false;
                };
                if saw_frame || !valid_baseline_frame(payload) {
                    return false;
                }
                saw_frame = true;
                offset = next;
            }
            0xc4 | 0xdb => {
                let Some((_, next)) = jpeg_segment(body, offset) else {
                    return false;
                };
                offset = next;
            }
            0xdd => {
                let Some((payload, next)) = jpeg_segment(body, offset) else {
                    return false;
                };
                if payload.len() != 2 {
                    return false;
                }
                offset = next;
            }
            0xda => {
                let Some((payload, scan_offset)) = jpeg_segment(body, offset) else {
                    return false;
                };
                return saw_frame
                    && valid_baseline_scan_header(payload)
                    && jpeg_scan_ends_cleanly(&body[scan_offset..]);
            }
            0xe0 => {
                let Some((payload, next)) = jpeg_segment(body, offset) else {
                    return false;
                };
                if saw_jfif || saw_frame || !valid_jfif(payload) {
                    return false;
                }
                saw_jfif = true;
                offset = next;
            }
            0xe1..=0xef | 0xfe => return false,
            _ => return false,
        }
    }
    false
}

fn jpeg_segment(body: &[u8], length_offset: usize) -> Option<(&[u8], usize)> {
    let length = usize::from(u16::from_be_bytes([
        *body.get(length_offset)?,
        *body.get(length_offset + 1)?,
    ]));
    if length < 2 {
        return None;
    }
    let end = length_offset.checked_add(length)?;
    Some((body.get(length_offset + 2..end)?, end))
}

fn valid_jfif(payload: &[u8]) -> bool {
    if payload.len() < 14 || !payload.starts_with(b"JFIF\0") {
        return false;
    }
    let thumbnail_bytes = usize::from(payload[12])
        .checked_mul(usize::from(payload[13]))
        .and_then(|pixels| pixels.checked_mul(3));
    thumbnail_bytes.is_some_and(|bytes| payload.len() == 14 + bytes)
}

fn valid_baseline_frame(payload: &[u8]) -> bool {
    if payload.len() < 6 || payload[0] != 8 {
        return false;
    }
    let height = u32::from(u16::from_be_bytes([payload[1], payload[2]]));
    let width = u32::from(u16::from_be_bytes([payload[3], payload[4]]));
    let components = usize::from(payload[5]);
    matches!(components, 1 | 3)
        && payload.len() == 6 + 3 * components
        && dimensions_within_limits(width, height)
}

fn valid_baseline_scan_header(payload: &[u8]) -> bool {
    let Some(&component_count) = payload.first() else {
        return false;
    };
    let component_count = usize::from(component_count);
    matches!(component_count, 1 | 3)
        && payload.len() == 1 + 2 * component_count + 3
        && payload[payload.len() - 3..] == [0, 63, 0]
}

fn jpeg_scan_ends_cleanly(scan: &[u8]) -> bool {
    let mut offset = 0;
    while offset < scan.len() {
        if scan[offset] != 0xff {
            offset += 1;
            continue;
        }
        while scan.get(offset) == Some(&0xff) {
            offset += 1;
        }
        let Some(&marker) = scan.get(offset) else {
            return false;
        };
        offset += 1;
        match marker {
            0x00 | 0xd0..=0xd7 => {}
            0xd9 => return offset == scan.len(),
            _ => return false,
        }
    }
    false
}

fn png_is_safe_to_transform(body: &[u8]) -> bool {
    if !body.starts_with(b"\x89PNG\r\n\x1a\n") {
        return false;
    }

    let mut offset = 8;
    let mut saw_header = false;
    let mut saw_palette = false;
    let mut saw_image_data = false;
    let mut color_type = 0;
    let mut bit_depth = 0;

    while offset < body.len() {
        let Some(length_bytes) = body.get(offset..offset + 4) else {
            return false;
        };
        let length = u32::from_be_bytes(length_bytes.try_into().unwrap()) as usize;
        let Some(chunk_type) = body.get(offset + 4..offset + 8) else {
            return false;
        };
        let data_start = offset + 8;
        let Some(data_end) = data_start.checked_add(length) else {
            return false;
        };
        let Some(chunk_end) = data_end.checked_add(4) else {
            return false;
        };
        let Some(data) = body.get(data_start..data_end) else {
            return false;
        };
        let Some(crc_bytes) = body.get(data_end..chunk_end) else {
            return false;
        };
        if !valid_png_chunk_type(chunk_type)
            || u32::from_be_bytes(crc_bytes.try_into().unwrap())
                != png_crc32(&body[offset + 4..data_end])
        {
            return false;
        }

        match chunk_type {
            b"IHDR" => {
                if saw_header || offset != 8 || data.len() != 13 {
                    return false;
                }
                let width = u32::from_be_bytes(data[0..4].try_into().unwrap());
                let height = u32::from_be_bytes(data[4..8].try_into().unwrap());
                bit_depth = data[8];
                color_type = data[9];
                if !dimensions_within_limits(width, height)
                    || !valid_png_color_type(bit_depth, color_type)
                    || data[10] != 0
                    || data[11] != 0
                    || data[12] != 0
                {
                    return false;
                }
                saw_header = true;
            }
            b"PLTE" => {
                if !saw_header
                    || saw_palette
                    || saw_image_data
                    || matches!(color_type, 0 | 4)
                    || data.is_empty()
                    || data.len() > 256 * 3
                    || data.len() % 3 != 0
                    || (color_type == 3 && data.len() / 3 > 1usize << bit_depth)
                {
                    return false;
                }
                saw_palette = true;
            }
            b"IDAT" => {
                if !saw_header || data.is_empty() || (color_type == 3 && !saw_palette) {
                    return false;
                }
                saw_image_data = true;
            }
            b"IEND" => {
                return saw_header && saw_image_data && data.is_empty() && chunk_end == body.len();
            }
            _ => return false,
        }

        offset = chunk_end;
    }
    false
}

fn valid_png_chunk_type(chunk_type: &[u8]) -> bool {
    chunk_type.len() == 4
        && chunk_type.iter().all(u8::is_ascii_alphabetic)
        && chunk_type[2].is_ascii_uppercase()
}

fn valid_png_color_type(bit_depth: u8, color_type: u8) -> bool {
    match color_type {
        0 => matches!(bit_depth, 1 | 2 | 4 | 8 | 16),
        2 => matches!(bit_depth, 8 | 16),
        3 => matches!(bit_depth, 1 | 2 | 4 | 8),
        4 | 6 => matches!(bit_depth, 8 | 16),
        _ => false,
    }
}

fn png_crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{
        codecs::{
            jpeg::JpegEncoder,
            png::{CompressionType, FilterType, PngEncoder},
        },
        ImageBuffer, ImageEncoder, Rgb,
    };

    fn transformable_jpeg() -> Vec<u8> {
        let image = ImageBuffer::from_fn(800, 600, |x, y| {
            Rgb([
                ((x * 31 + y * 7) % 256) as u8,
                ((x * 13 + y * 29) % 256) as u8,
                ((x * 3 + y * 17) % 256) as u8,
            ])
        });
        let mut source = Vec::new();
        JpegEncoder::new_with_quality(&mut source, 100)
            .encode_image(&DynamicImage::ImageRgb8(image))
            .unwrap();
        source
    }

    fn with_jpeg_segment(source: &[u8], marker: u8, payload: &[u8]) -> Vec<u8> {
        assert_eq!(&source[..2], b"\xff\xd8");
        let length = u16::try_from(payload.len() + 2).unwrap();
        let mut segment = vec![0xff, marker];
        segment.extend_from_slice(&length.to_be_bytes());
        segment.extend_from_slice(payload);

        let mut result = source.to_vec();
        result.splice(2..2, segment);
        result
    }

    fn with_jpeg_dimensions(source: &[u8], width: u16, height: u16) -> Vec<u8> {
        let mut result = source.to_vec();
        let frame = result
            .windows(2)
            .position(|window| window == b"\xff\xc0")
            .unwrap();
        result[frame + 5..frame + 7].copy_from_slice(&height.to_be_bytes());
        result[frame + 7..frame + 9].copy_from_slice(&width.to_be_bytes());
        result
    }

    fn transformable_png() -> Vec<u8> {
        let image = ImageBuffer::from_fn(320, 240, |x, y| {
            Rgb([
                ((x / 16) % 4 * 64) as u8,
                ((y / 16) % 4 * 64) as u8,
                (((x + y) / 32) % 4 * 64) as u8,
            ])
        });
        let mut source = Vec::new();
        PngEncoder::new_with_quality(
            &mut source,
            CompressionType::Uncompressed,
            FilterType::NoFilter,
        )
        .write_image(
            image.as_raw(),
            image.width(),
            image.height(),
            ExtendedColorType::Rgb8,
        )
        .unwrap();
        source
    }

    fn fixture_png_crc32(bytes: &[u8]) -> u32 {
        let mut crc = u32::MAX;
        for byte in bytes {
            crc ^= u32::from(*byte);
            for _ in 0..8 {
                let mask = 0u32.wrapping_sub(crc & 1);
                crc = (crc >> 1) ^ (0xedb8_8320 & mask);
            }
        }
        !crc
    }

    fn with_png_chunk(source: &[u8], chunk_type: &[u8; 4], data: &[u8]) -> Vec<u8> {
        assert_eq!(&source[..8], b"\x89PNG\r\n\x1a\n");
        assert_eq!(&source[12..16], b"IHDR");
        let mut chunk = Vec::new();
        chunk.extend_from_slice(&u32::try_from(data.len()).unwrap().to_be_bytes());
        chunk.extend_from_slice(chunk_type);
        chunk.extend_from_slice(data);
        chunk.extend_from_slice(&fixture_png_crc32(&chunk[4..]).to_be_bytes());

        let mut result = source.to_vec();
        result.splice(33..33, chunk);
        result
    }

    fn with_png_dimensions(source: &[u8], width: u32, height: u32) -> Vec<u8> {
        let mut result = source.to_vec();
        result[16..20].copy_from_slice(&width.to_be_bytes());
        result[20..24].copy_from_slice(&height.to_be_bytes());
        let crc = fixture_png_crc32(&result[12..29]);
        result[29..33].copy_from_slice(&crc.to_be_bytes());
        result
    }

    #[test]
    fn tiny_images_are_never_transformed() {
        assert!(transform_image(
            b"not an image",
            "image/jpeg",
            true,
            CompressionPreset::Maximum
        )
        .is_none());
    }

    #[test]
    fn metadata_bearing_jpeg_falls_back_to_the_original() {
        let mut body = vec![0u8; MIN_IMAGE_BYTES];
        body[100..106].copy_from_slice(b"Exif\0\0");
        assert!(transform_image(&body, "image/jpeg", true, CompressionPreset::Maximum).is_none());
    }

    #[test]
    fn structural_jpeg_metadata_falls_back_to_the_original() {
        let source = transformable_jpeg();
        assert!(
            transform_image(&source, "image/jpeg", false, CompressionPreset::Maximum).is_some()
        );

        for (marker, payload) in [
            (0xfe, b"comment".as_slice()),
            (0xe1, b"Exif\0\0payload".as_slice()),
            (0xe1, b"http://ns.adobe.com/xap/1.0/\0<xmp/>".as_slice()),
            (0xe2, b"ICC_PROFILE\0payload".as_slice()),
            (0xed, b"Photoshop 3.0\0IPTC".as_slice()),
        ] {
            let with_metadata = with_jpeg_segment(&source, marker, payload);
            assert!(
                transform_image(
                    &with_metadata,
                    "image/jpeg",
                    false,
                    CompressionPreset::Maximum
                )
                .is_none(),
                "marker {marker:#04x}"
            );
        }
    }

    #[test]
    fn png_text_color_and_animation_chunks_fall_back_to_the_original() {
        let source = transformable_png();
        assert!(transform_image(&source, "image/png", true, CompressionPreset::Maximum).is_some());

        for (chunk_type, data) in [
            (b"tEXt", b"Comment\0hello".as_slice()),
            (b"gAMA", 45_455u32.to_be_bytes().as_slice()),
            (b"acTL", [0, 0, 0, 1, 0, 0, 0, 0].as_slice()),
        ] {
            let with_metadata = with_png_chunk(&source, chunk_type, data);
            assert!(
                transform_image(
                    &with_metadata,
                    "image/png",
                    true,
                    CompressionPreset::Maximum
                )
                .is_none(),
                "chunk {:?}",
                std::str::from_utf8(chunk_type).unwrap()
            );
        }
    }

    #[test]
    fn oversized_dimensions_are_rejected_from_headers_without_decoding() {
        let jpeg = transformable_jpeg();
        assert!(jpeg_is_safe_to_transform(&jpeg));
        assert!(!jpeg_is_safe_to_transform(&with_jpeg_dimensions(
            &jpeg,
            (MAX_DIMENSION + 1) as u16,
            1
        )));

        let png = transformable_png();
        assert!(png_is_safe_to_transform(&png));
        assert!(!png_is_safe_to_transform(&with_png_dimensions(
            &png,
            MAX_DIMENSION + 1,
            1
        )));
        assert!(!png_is_safe_to_transform(&with_png_dimensions(
            &png, 4_000, 4_000
        )));
    }

    #[test]
    fn malformed_jpeg_segments_and_png_chunks_are_rejected() {
        let jpeg = transformable_jpeg();
        let mut invalid_segment_length = jpeg.clone();
        invalid_segment_length.splice(2..2, [0xff, 0xfe, 0, 1]);
        assert!(!jpeg_is_safe_to_transform(&invalid_segment_length));

        let png = transformable_png();
        let mut invalid_crc = png.clone();
        invalid_crc[29] ^= 1;
        assert!(!png_is_safe_to_transform(&invalid_crc));

        let mut truncated = png;
        truncated.pop();
        assert!(!png_is_safe_to_transform(&truncated));
    }

    #[test]
    fn noisy_jpeg_can_be_reencoded_when_the_saving_is_real() {
        let source = transformable_jpeg();
        let transformed =
            transform_image(&source, "image/jpeg", false, CompressionPreset::Maximum).unwrap();
        assert_eq!(transformed.content_type, "image/jpeg");
        assert!(transformed.saved_bytes >= MIN_SAVING_BYTES as u64);
    }
}
