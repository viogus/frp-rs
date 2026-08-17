//! CRC-32C (Castagnoli) checksum, used by the Snappy frame format for the
//! per-chunk checksum.
//!
//! The Snappy frame format ([framing format
//! spec](https://github.com/google/snappy/blob/master/framing_format.txt))
//! stores a "masked" CRC-32C of each chunk's *uncompressed* data in the
//! frame. Go frp's `golang/snappy` reader verifies this checksum, so every
//! compressed frame this crate emits must carry a correct one.
//!
//! The implementation is a plain 256-entry lookup table with the reflected
//! Castagnoli polynomial `0x82F63B78` (init register `0xFFFFFFFF`, final XOR
//! `0xFFFFFFFF`) — byte-at-a-time, no `unsafe`, no CPU-feature dispatch. It
//! is byte-identical to the checksums produced by `golang/snappy` and the
//! `snap` crate (both use the same CRC-32C); the test module cross-checks
//! against the `snap` reference encoder's frame checksum.

/// 256-entry CRC-32C remainder table, indexed by the incoming byte XOR-ed
/// into the low byte of the working register (reflected CRC).
static CRC32C_TABLE: [u32; 256] = build_crc32c_table();

/// Build the CRC-32C lookup table by simulating 8 bitwise reduction steps
/// per table entry (Castagnoli polynomial `0x82F63B78`, reflected form).
const fn build_crc32c_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0x82F63B78
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

/// Compute the CRC-32C (Castagnoli) checksum of `data`.
///
/// Standard reflected form: initial register `0xFFFFFFFF`, final XOR
/// `0xFFFFFFFF`, polynomial `0x82F63B78`. Matches the checksum used by
/// `golang/snappy` and the `snap` crate.
pub fn crc32c(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc = CRC32C_TABLE[((crc ^ b as u32) & 0xff) as usize] ^ (crc >> 8);
    }
    !crc
}

/// Snappy frame-format "masked" CRC-32C of `data`.
///
/// The masking transform makes the checksum robust to the checksum itself
/// appearing inside the payload it covers:
/// `(crc >> 15 | crc << 17) + 0xA282EAD8` (wrapping 32-bit arithmetic).
/// This is the exact value written (little-endian) into each Snappy data
/// frame, and what `golang/snappy`'s reader verifies on decode.
pub fn crc32c_masked(data: &[u8]) -> u32 {
    let sum = crc32c(data);
    sum.rotate_right(15).wrapping_add(0xA282_EAD8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_has_zero_checksum() {
        assert_eq!(crc32c(b""), 0x0000_0000);
    }

    #[test]
    fn classic_check_value() {
        // The standard CRC-32C check value for the ASCII string "123456789".
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
    }

    #[test]
    fn known_vector() {
        // Cross-validated against the `snap` reference encoder's frame
        // checksum for the same input (see
        // masked_matches_snap_reference_frame_checksum below): `snap`'s
        // writer computes 0xC99465AA for "hello world", and our function
        // must agree byte-for-byte with it, so that is the value the wire
        // needs. (Some secondary references quote other values such as
        // 0xD4A1185C; the reference encoder output is the ground truth
        // here.)
        assert_eq!(crc32c(b"hello world"), 0xC994_65AA);
    }

    #[test]
    fn masked_empty_is_the_mask_constant() {
        // Masking of the zero checksum is the additive constant itself.
        assert_eq!(crc32c_masked(b""), 0xA282_EAD8);
    }

    #[test]
    fn masked_matches_snap_reference_frame_checksum() {
        // Ground truth: compress through the `snap` reference encoder and
        // read the 4-byte masked checksum out of its frame header. Our
        // masked CRC must equal it for the same uncompressed bytes.
        use std::io::Write;
        let mut out = Vec::new();
        let mut enc = snap::write::FrameEncoder::new(&mut out);
        enc.write_all(b"hello world").unwrap();
        enc.into_inner().unwrap();
        assert_eq!(&out[0..10], b"\xff\x06\x00\x00sNaPpY");
        // Frame header: 4-byte chunk header at 10..14, then 4-byte checksum.
        let crc_le = u32::from_le_bytes(out[14..18].try_into().unwrap());
        assert_eq!(crc_le, crc32c_masked(b"hello world"));
    }

    #[test]
    fn masked_matches_snap_reference_frame_checksum_large() {
        // Same cross-check on a >64 KiB input that splits across frames and
        // exercises both compressed and uncompressed chunk decisions. The
        // reference encoder splits input into 64 KiB blocks (one frame per
        // block), so each frame's checksum must equal ours over the
        // corresponding 64 KiB slice of the original data.
        use std::io::Write;
        let data: Vec<u8> = (0u64..70_000)
            .map(|i| (i.wrapping_mul(131) >> 7) as u8)
            .collect();
        let mut out = Vec::new();
        let mut enc = snap::write::FrameEncoder::new(&mut out);
        enc.write_all(&data).unwrap();
        enc.into_inner().unwrap();
        // Walk the frames, verifying each chunk's checksum against ours.
        let mut pos = 10; // skip the stream identifier
        let mut block_start = 0usize;
        let mut data_frames = 0usize;
        while pos + 4 <= out.len() {
            let chunk_type = out[pos];
            assert_ne!(chunk_type, 0xff, "identifier must appear only once");
            let chunk_len =
                u32::from_le_bytes([out[pos + 1], out[pos + 2], out[pos + 3], 0]) as usize;
            assert!(chunk_len >= 4, "checksum must be present");
            let crc_le = u32::from_le_bytes(out[pos + 4..pos + 8].try_into().unwrap());
            let block_end = (block_start + 64 * 1024).min(data.len());
            assert_eq!(
                crc_le,
                crc32c_masked(&data[block_start..block_end]),
                "frame at offset {pos} (type 0x{chunk_type:02x})"
            );
            block_start = block_end;
            data_frames += 1;
            pos += 4 + chunk_len;
        }
        assert_eq!(block_start, data.len());
        assert!(data_frames >= 2, "expected multiple data frames");
    }
}
