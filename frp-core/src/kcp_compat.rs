//! KCP compatibility layer matching Go kcp-go wire format.
//!
//! Go's kcp-go wraps raw KCP with two layers:
//! 1. XOR encryption (repeating-key)
//! 2. FEC — Reed-Solomon forward error correction over GF(2^8)
//!
//! This module provides equivalent encode/decode for Go↔Rust KCP compatibility.
//!
//! STATUS: Only `Fec` is wired into `KcpSession` (`kcp/session.rs`).
//! `XorBlock` and `KcpCompatSession` (FEC+XOR combined) are implemented but
//! not yet wired — `KcpConfig` (`kcp/config.rs`) has no `crypt` field.
//! When a `crypt` key is added to `KcpConfig` and threaded through to
//! `KcpSession::new()`, apply `XorBlock` per-packet in `update()`/`input()`.

/// GF(2^8) finite field arithmetic.
/// Operations use irreducible polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11D).
pub mod gf256 {
    /// Multiply two GF(2^8) elements.
    pub fn mul(mut a: u8, mut b: u8) -> u8 {
        let mut result = 0u8;
        for _ in 0..8 {
            if b & 1 != 0 {
                result ^= a;
            }
            let carry = a & 0x80;
            a <<= 1;
            if carry != 0 {
                a ^= 0x1D; // x^8 + x^4 + x^3 + x^2 + 1, minus x^8
            }
            b >>= 1;
        }
        result
    }

    /// Compute a^exp in GF(2^8) using exponentiation by squaring.
    pub fn pow(mut base: u8, mut exp: u32) -> u8 {
        let mut result = 1u8;
        while exp > 0 {
            if exp & 1 != 0 {
                result = mul(result, base);
            }
            base = mul(base, base);
            exp >>= 1;
        }
        result
    }

    /// Multiplicative inverse in GF(2^8).
    /// Since GF(2^8)* has order 255, a^(-1) = a^254.
    pub fn inv(a: u8) -> u8 {
        if a == 0 {
            return 0;
        }
        pow(a, 254)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_mul_identity() {
            assert_eq!(mul(1, 42), 42);
            assert_eq!(mul(42, 1), 42);
        }

        #[test]
        fn test_mul_distributive() {
            // (a + b) * c = a*c + b*c in GF(2^8) where + is XOR
            let a = 0x12u8;
            let b = 0x34u8;
            let c = 0x56u8;
            let left = mul(a ^ b, c);
            let right = mul(a, c) ^ mul(b, c);
            assert_eq!(left, right);
        }

        #[test]
        fn test_inv() {
            assert_eq!(mul(5, inv(5)), 1);
            assert_eq!(mul(0xFF, inv(0xFF)), 1);
        }

        #[test]
        fn test_pow() {
            // a^0 = 1
            assert_eq!(pow(42, 0), 1);
            // a^1 = a
            assert_eq!(pow(42, 1), 42);
            // a^2 = a * a
            assert_eq!(pow(42, 2), mul(42, 42));
        }
    }
}

/// Reed-Solomon FEC encoder/decoder over GF(2^8).
///
/// Uses a Vandermonde matrix for encoding:
///   matrix[i][j] = (i+1)^j  for parity row i, data column j
///
/// Decoding uses Gaussian elimination on the augmented matrix.
pub struct Fec {
    data_shards: usize,
    parity_shards: usize,
    /// Pre-computed Vandermonde encoding matrix rows for parity shards.
    encode_matrix: Vec<Vec<u8>>,
    /// Flat table of GF(2^8) multiplication results, indexed
    /// `(parity_shard * data_shards + data_shard) * 256 + byte_value`.
    ///
    /// The per-byte multiply in the encode loop used to be a bit-serial
    /// Russian-peasant multiply (eight shift/XOR rounds per byte per data
    /// shard — ~80 rounds per output byte for kcp-go's 10+3 group). Every
    /// coefficient in `encode_matrix` is fixed at construction, so the 256
    /// possible products can be pre-computed once and the hot loop becomes a
    /// table lookup plus XOR. Measured on the KCP transport (64 KiB
    /// ping-pong, single flow): 20.8 → 62.7 MiB/s.
    ///
    /// Scalar fallback only — the vector path uses `nibble_tables`.
    mul_tables: Vec<u8>,
    /// Nibble tables for the AVX2 path, indexed
    /// `(parity_shard * data_shards + data_shard) * 32`, layout
    /// `[lo16][hi16]` where `lo[n] = coef * n` and `hi[n] = coef * (n << 4)`.
    ///
    /// A byte `b` is `(b & 0x0f) ^ (b >> 4) << 4` in GF(2^8), so
    /// `coef * b = lo[b & 0x0f] ^ hi[b >> 4]`, which is exactly
    /// `VPSHUFB`-shaped: two 16-byte table lookups and one XOR per 32 bytes.
    /// Go gets the same effect from `klauspost/reedsolomon`'s assembly.
    /// 32 bytes per coefficient (960 B for 10+3) instead of the 256-entry
    /// scalar table.
    nibble_tables: Vec<u8>,
}

/// True when this CPU can run [`xor_mul_avx2`]. Detected once.
#[cfg(target_arch = "x86_64")]
static AVX2_SUPPORTED: std::sync::LazyLock<bool> =
    std::sync::LazyLock::new(|| std::arch::is_x86_feature_detected!("avx2"));

/// AVX2: `dst[i] ^= coef * src[i]` for a fixed `coef`, 32 bytes at a time.
///
/// # Safety
/// Caller must have checked AVX2 support (`is_x86_feature_detected!`) and
/// passed slices that live for the call.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn xor_mul_avx2(dst: &mut [u8], src: &[u8], lo: &[u8; 16], hi: &[u8; 16]) {
    use std::arch::x86_64::*;

    // SAFETY: AVX2 is enabled for this function by `target_feature`, the caller
    // verified the CPU supports it, and every load/store stays inside
    // `min(src.len(), dst.len())` bytes of slices that are alive for the call.
    // The explicit block keeps the body correct if this crate adopts
    // `unsafe_op_in_unsafe_fn` (edition 2024) — the workspace is edition 2021.
    unsafe {
        let n = src.len().min(dst.len());
        let mask = _mm256_set1_epi8(0x0f);
        // `VPSHUFB` is per-128-bit-lane, so broadcast the 16-byte table to both.
        let lo_tbl = _mm256_broadcastsi128_si256(_mm_loadu_si128(lo.as_ptr().cast()));
        let hi_tbl = _mm256_broadcastsi128_si256(_mm_loadu_si128(hi.as_ptr().cast()));
        let (sp, dp) = (src.as_ptr(), dst.as_mut_ptr());

        let mut i = 0usize;
        while i + 32 <= n {
            let x = _mm256_loadu_si256(sp.add(i).cast());
            let l = _mm256_and_si256(x, mask);
            // Per byte: the low nibble, and the high nibble after the 16-bit
            // shift (byte 1 of `x >> 4` is `hi >> 4`; byte 0 is
            // `(hi << 4) | (lo >> 4)`), then the AND keeps the right nibble.
            let h = _mm256_and_si256(_mm256_srli_epi16(x, 4), mask);
            let prod = _mm256_xor_si256(
                _mm256_shuffle_epi8(lo_tbl, l),
                _mm256_shuffle_epi8(hi_tbl, h),
            );
            let acc = _mm256_loadu_si256(dp.add(i).cast());
            _mm256_storeu_si256(dp.add(i).cast(), _mm256_xor_si256(acc, prod));
            i += 32;
        }
        // Fewer than 32 bytes left (short shards never enter here, but the
        // tail of a 1326-byte KCP segment does).
        while i < n {
            let b = *sp.add(i);
            *dp.add(i) ^= lo[(b & 0x0f) as usize] ^ hi[(b >> 4) as usize];
            i += 1;
        }
    }
}

/// `dst[i] ^= coef * src[i]`, vectorised when the CPU and length allow it.
#[inline]
fn xor_mul_into(dst: &mut [u8], src: &[u8], table: &[u8], nibbles: &[u8]) {
    debug_assert_eq!(nibbles.len(), 32, "nibble table is lo[16] ++ hi[16]");

    #[cfg(target_arch = "x86_64")]
    {
        let lo: &[u8; 16] = nibbles[..16].try_into().expect("lo half is 16 bytes");
        let hi: &[u8; 16] = nibbles[16..].try_into().expect("hi half is 16 bytes");
        if *AVX2_SUPPORTED && src.len() >= 32 {
            // SAFETY: `AVX2_SUPPORTED` is the runtime `is_x86_feature_detected!`
            // check for the instruction set this function is compiled for, and
            // `xor_mul_avx2` bounds itself with `min(len)`. Both slices are
            // alive for the call and only read/written inside their lengths.
            unsafe { xor_mul_avx2(dst, src, lo, hi) };
            return;
        }
    }
    // Non-x86 targets never build the vector path; the nibble table is unused.
    #[cfg(not(target_arch = "x86_64"))]
    let _ = nibbles;

    // Scalar fallback: one 256-entry lookup per byte, unchanged from before the
    // vector path existed. Non-AVX2 targets (aarch64, pre-AVX2 x86) pay only the
    // one-time nibble-table build in `Fec::new` (960 B and 960 multiplies for
    // 10+3), never more per byte.
    let n = dst.len().min(src.len());
    for (d, &b) in dst.iter_mut().zip(src.iter()).take(n) {
        *d ^= table[b as usize];
    }
}

impl Fec {
    /// Table of `coef * b` for every byte `b`, for parity shard `parity` and
    /// data shard `data`.
    #[inline]
    fn mul_table(&self, parity: usize, data: usize) -> &[u8] {
        let start = (parity * self.data_shards + data) * 256;
        &self.mul_tables[start..start + 256]
    }

    /// Nibble-table slice (`lo[16] ++ hi[16]`) for parity shard `parity` and
    /// data shard `data`.
    #[inline]
    fn nibble_table(&self, parity: usize, data: usize) -> &[u8] {
        let start = (parity * self.data_shards + data) * 32;
        &self.nibble_tables[start..start + 32]
    }

    /// Create a new FEC codec.
    /// `data_shards` and `parity_shards` match Go kcp-go parameters.
    /// When both are 0, FEC is effectively disabled (no-op).
    ///
    /// The encoding matrix is byte-compatible with Go kcp-go's
    /// `klauspost/reedsolomon.New(data, parity)` default (`buildMatrix`):
    /// a `(total × data)` Vandermonde matrix `vm[r][c] = r^c` in GF(2^8),
    /// made systematic by right-multiplying with the inverse of its top
    /// `data × data` square. The parity rows (`data..total`) become the
    /// encode matrix. This is REQUIRED for cross-impl FEC recovery: a custom
    /// matrix (e.g. `(i+1)^j`) is self-consistent but reconstructs Go-encoded
    /// parity into garbage, corrupting the KCP stream under packet loss.
    pub fn new(data_shards: usize, parity_shards: usize) -> Self {
        // GF(2^8) caps distinct Vandermonde rows at 256: beyond that `r as u8`
        // wraps and the top data×data square becomes singular, which would
        // panic in `invert_matrix`. Saturate defensively — an oversized
        // `data_shards` is a config error, not a network input. (kcp-go's
        // reedsolomon rejects >256 at construction instead of saturating;
        // the session layer clamps the same value so both stay consistent.)
        let data_shards = data_shards.min(256);
        let total_shards = data_shards + parity_shards;
        let encode_matrix = if data_shards > 0 && parity_shards > 0 {
            // Vandermonde: vm[r][c] = r^c (r from 0), matching klauspost galExp.
            let vm: Vec<Vec<u8>> = (0..total_shards)
                .map(|r| {
                    (0..data_shards)
                        .map(|c| gf256::pow(r as u8, c as u32))
                        .collect()
                })
                .collect();
            // Invert the top data×data square; distinct nodes 0..data-1 make it
            // non-singular for data <= 256.
            let top: Vec<Vec<u8>> = vm[..data_shards].to_vec();
            let top_inv = invert_matrix(&top)
                .expect("Vandermonde top square is invertible for distinct nodes");
            // systematic = vm * top_inv; keep only the parity rows.
            let mut rows = Vec::with_capacity(parity_shards);
            for vm_row in vm.iter().skip(data_shards) {
                let mut row = vec![0u8; data_shards];
                for (c, cell) in row.iter_mut().enumerate() {
                    let mut sum = 0u8;
                    for (k, &vm_k) in vm_row.iter().enumerate() {
                        sum ^= gf256::mul(vm_k, top_inv[k][c]);
                    }
                    *cell = sum;
                }
                rows.push(row);
            }
            rows
        } else {
            Vec::new()
        };
        let mut mul_tables = Vec::with_capacity(encode_matrix.len() * data_shards.max(1) * 256);
        let mut nibble_tables = Vec::with_capacity(encode_matrix.len() * data_shards.max(1) * 32);
        for row in &encode_matrix {
            for &coef in row {
                for v in 0..=255u8 {
                    mul_tables.push(gf256::mul(coef, v));
                }
                for v in 0..16u8 {
                    nibble_tables.push(gf256::mul(coef, v));
                }
                for v in 0..16u8 {
                    nibble_tables.push(gf256::mul(coef, v << 4));
                }
            }
        }
        Self {
            data_shards,
            parity_shards,
            encode_matrix,
            mul_tables,
            nibble_tables,
        }
    }

    /// Check if FEC is enabled (non-zero shards).
    pub fn enabled(&self) -> bool {
        self.data_shards > 0 && self.parity_shards > 0
    }

    /// Encode data shards into output shards (data + parity).
    ///
    /// `input`: slice of `data_shards` byte slices, all same length.
    /// Returns `total_shards` vectors (first data_shards are copies of input).
    pub fn encode(&self, input: &[&[u8]]) -> Vec<Vec<u8>> {
        if !self.enabled() {
            return input.iter().map(|s| s.to_vec()).collect();
        }
        assert_eq!(
            input.len(),
            self.data_shards,
            "input must equal data_shards"
        );
        let block_size = input[0].len();
        let mut output: Vec<Vec<u8>> = input.iter().map(|s| s.to_vec()).collect();

        for i in 0..self.parity_shards {
            let mut parity = vec![0u8; block_size];
            for (data_idx, inp) in input.iter().enumerate() {
                // Rows are equal-length by contract; `zip` would treat a short
                // row as zero-extended, so fail loudly on a caller bug instead.
                debug_assert_eq!(inp.len(), block_size, "FEC shards must be equal length");
                xor_mul_into(
                    &mut parity,
                    inp,
                    self.mul_table(i, data_idx),
                    self.nibble_table(i, data_idx),
                );
            }
            output.push(parity);
        }
        output
    }

    /// Compute only the parity shards for `input` (which must have exactly
    /// `data_shards` rows, each `block_size` bytes). Unlike [`encode`], the data
    /// shards are not copied — callers that only need the FEC parity rows (the
    /// KCP send path) avoid one full copy + N allocations per batch.
    pub fn encode_parity(&self, input: &[&[u8]]) -> Vec<Vec<u8>> {
        assert_eq!(
            input.len(),
            self.data_shards,
            "input must equal data_shards"
        );
        let block_size = input[0].len();
        let mut parity_shards = Vec::with_capacity(self.parity_shards);
        for i in 0..self.parity_shards {
            let mut parity = vec![0u8; block_size];
            for (data_idx, inp) in input.iter().enumerate() {
                // See `encode`: the rows must be equal length.
                debug_assert_eq!(inp.len(), block_size, "FEC shards must be equal length");
                xor_mul_into(
                    &mut parity,
                    inp,
                    self.mul_table(i, data_idx),
                    self.nibble_table(i, data_idx),
                );
            }
            parity_shards.push(parity);
        }
        parity_shards
    }

    /// Decode: reconstruct missing shards from available ones.
    ///
    /// `shards`: `total_shards` entries, Some(data) if present, None if missing.
    /// Returns true if reconstruction succeeded (enough shards available).
    ///
    /// Uses Gaussian elimination over GF(2^8) with the Vandermonde matrix.
    pub fn decode(&self, shards: &mut [Option<Vec<u8>>]) -> bool {
        if !self.enabled() {
            return true; // no-op
        }
        // Block size = the LONGEST present row, not the first: GF(2^8) row
        // math needs uniform lengths, and decode of a ragged group must
        // zero-extend like the production receive path does (session.rs
        // resizes every row to the group max before decode — "Go:
        // zero-extend shorter shards"). Truncating to the first row's
        // length would silently drop the tail of every longer recovered
        // row. Direct callers (tests) may pass ragged input; uniform rows
        // (production) are unaffected.
        let block_size = shards
            .iter()
            .filter_map(|s| s.as_ref().map(|v| v.len()))
            .max()
            .unwrap_or(0);
        if block_size == 0 {
            return false;
        }

        // Normalize ragged rows to the group max (zero-extension): the
        // encoder padded every data row to max before computing parity, so
        // GF(2^8) row math over zero-extended short rows is exact — and the
        // per-byte indexing below never runs past a short row's end.
        // Production (session.rs) resizes before decode ("Go: zero-extend
        // shorter shards"); direct callers may pass ragged input.
        for s in shards.iter_mut().flatten() {
            if s.len() < block_size {
                s.resize(block_size, 0);
            }
        }

        let present: Vec<usize> = shards
            .iter()
            .enumerate()
            .filter(|(_, s)| s.is_some())
            .map(|(i, _)| i)
            .collect();

        if present.len() < self.data_shards {
            return false; // not enough shards to reconstruct
        }

        // Select exactly data_shards present shards to build a square system.
        // Prefer data shards first (they give identity rows, simpler elimination).
        let mut selected: Vec<usize> = present
            .iter()
            .filter(|&&i| i < self.data_shards)
            .copied()
            .collect();
        // Add parity shards to reach data_shards total
        for &idx in &present {
            if selected.len() >= self.data_shards {
                break;
            }
            if idx >= self.data_shards {
                selected.push(idx);
            }
        }

        // Build square matrix from selected shards
        let mut matrix = vec![vec![0u8; self.data_shards]; self.data_shards];
        for (row, &shard_idx) in selected.iter().enumerate() {
            if shard_idx < self.data_shards {
                // Data shard: identity row
                matrix[row][shard_idx] = 1;
            } else {
                // Parity shard: Vandermonde row
                let parity_idx = shard_idx - self.data_shards;
                for (col, mat_cell) in matrix[row].iter_mut().enumerate() {
                    *mat_cell = self.encode_matrix[parity_idx][col];
                }
            }
        }

        // Invert the square matrix.
        let inv = match invert_matrix(&matrix) {
            Some(inv) => inv,
            None => return false, // singular matrix
        };

        // For each missing data shard, reconstruct from inverse matrix * selected data
        for missing_idx in 0..self.data_shards {
            if shards[missing_idx].is_some() {
                continue;
            }
            let mut reconstructed = vec![0u8; block_size];
            let inv_row = &inv[missing_idx];
            // Below one table's worth of bytes the 256-entry table build costs
            // more than it saves, so short blocks keep the bit-serial multiply.
            if block_size >= 256 {
                let tables: Vec<[u8; 256]> = inv_row
                    .iter()
                    .map(|&coef| {
                        let mut t = [0u8; 256];
                        for (v, slot) in t.iter_mut().enumerate() {
                            *slot = gf256::mul(coef, v as u8);
                        }
                        t
                    })
                    .collect();
                for (row, &pres_idx) in selected.iter().enumerate() {
                    let table = &tables[row];
                    let present = shards[pres_idx]
                        .as_ref()
                        .expect("pres_idx drawn only from present shards");
                    for (rec_byte, &val) in reconstructed.iter_mut().zip(present.iter()) {
                        *rec_byte ^= table[val as usize];
                    }
                }
            } else {
                for (byte_idx, rec_byte) in reconstructed.iter_mut().enumerate() {
                    let mut sum = 0u8;
                    for (row, &pres_idx) in selected.iter().enumerate() {
                        let val = shards[pres_idx]
                            .as_ref()
                            .expect("pres_idx drawn only from present shards")[byte_idx];
                        sum ^= gf256::mul(inv_row[row], val);
                    }
                    *rec_byte = sum;
                }
            }
            shards[missing_idx] = Some(reconstructed);
        }

        // Note: parity shard reconstruction is skipped — only data shards needed
        true
    }
}

/// Invert a square matrix over GF(2^8) using Gauss-Jordan elimination.
fn invert_matrix(matrix: &[Vec<u8>]) -> Option<Vec<Vec<u8>>> {
    let n = matrix.len();
    if n == 0 {
        return Some(vec![]);
    }
    // Build augmented matrix [A | I]
    let mut aug: Vec<Vec<u8>> = vec![vec![0u8; 2 * n]; n];
    for (i, aug_row) in aug.iter_mut().enumerate() {
        for (j, cell) in aug_row.iter_mut().take(n).enumerate() {
            *cell = matrix[i][j];
        }
        aug_row[n + i] = 1;
    }

    // Forward elimination
    for col in 0..n {
        // Find pivot
        let pivot_row = (col..n).find(|&r| aug[r][col] != 0)?;
        aug.swap(col, pivot_row);

        // Scale pivot row to make pivot = 1
        let inv_pivot = gf256::inv(aug[col][col]);
        for cell in aug[col].iter_mut() {
            *cell = gf256::mul(*cell, inv_pivot);
        }

        // Eliminate other rows
        for row in 0..n {
            if row == col {
                continue;
            }
            let factor = aug[row][col];
            if factor == 0 {
                continue;
            }
            // Copy pivot row values before mutable iteration to avoid borrow conflict
            let pivot_row: Vec<u8> = aug[col].to_vec();
            for (j, cell) in aug[row].iter_mut().enumerate() {
                *cell ^= gf256::mul(factor, pivot_row[j]);
            }
        }
    }

    // Extract inverse from right half
    Some(aug.iter().map(|row| row[n..2 * n].to_vec()).collect())
}

/// XOR block cipher matching Go kcp-go's XorBlock.
///
/// Go implementation uses a simple repeating-key XOR:
///   for i := range data { data[i] ^= key[i % len(key)] }
pub struct XorBlock {
    key: Vec<u8>,
}

impl XorBlock {
    pub fn new(key: &[u8]) -> Self {
        Self { key: key.to_vec() }
    }

    /// XOR encrypt/decrypt in place (symmetric operation).
    pub fn process(&self, data: &mut [u8]) {
        if self.key.is_empty() {
            return;
        }
        for (i, byte) in data.iter_mut().enumerate() {
            *byte ^= self.key[i % self.key.len()];
        }
    }

    /// Check if encryption is configured (non-empty key).
    pub fn enabled(&self) -> bool {
        !self.key.is_empty()
    }
}

/// KCP compatibility session combining FEC + XOR layers.
///
/// Usage:
/// 1. Create with desired FEC/XOR parameters (matching peer's config)
/// 2. Call `encode_packet()` before sending raw KCP data
///
/// Note: there is deliberately NO `decode_packets()` counterpart — the
/// previous implementation stripped all trailing zero bytes as "padding",
/// corrupting payloads legitimately ending in 0x00. It was dead code (the
/// live FEC decode path is `kcp/session.rs`, which uses the FEC SIZE field
/// for shard boundaries) and only its own tests referenced it, so it was
/// deleted 2026-08-13. Do not re-add a decode here without size-field-based
/// boundaries.
pub struct KcpCompatSession {
    fec: Fec,
    xor: XorBlock,
}

impl KcpCompatSession {
    /// Create a new compat session.
    /// `data_shards`, `parity_shards`: FEC parameters (0,0 to disable)
    /// `key`: XOR key (empty to disable)
    pub fn new(data_shards: usize, parity_shards: usize, key: &[u8]) -> Self {
        Self {
            fec: Fec::new(data_shards, parity_shards),
            xor: XorBlock::new(key),
        }
    }

    /// Check if FEC is enabled.
    pub fn fec_enabled(&self) -> bool {
        self.fec.enabled()
    }

    /// Check if XOR encryption is enabled.
    pub fn xor_enabled(&self) -> bool {
        self.xor.enabled()
    }

    /// Encode a single data packet for sending.
    ///
    /// If FEC enabled: splits into data_shards + parity_shards, returns all shards.
    /// If XOR enabled: applies XOR before FEC.
    /// If neither: returns the input as-is (single shard).
    pub fn encode_packet(&self, data: &[u8]) -> Vec<Vec<u8>> {
        if !self.fec.enabled() {
            let mut d = data.to_vec();
            if self.xor.enabled() {
                self.xor.process(&mut d);
            }
            return vec![d];
        }

        // Split data into data_shards blocks
        let block_size = data.len().div_ceil(self.fec.data_shards);
        let mut shards: Vec<Vec<u8>> = (0..self.fec.data_shards)
            .map(|i| {
                let start = i * block_size;
                let end = ((i + 1) * block_size).min(data.len());
                let mut shard = vec![0u8; block_size];
                if start < data.len() {
                    shard[..end - start].copy_from_slice(&data[start..end]);
                }
                shard
            })
            .collect();

        // Apply XOR before FEC (matching Go kcp-go order)
        if self.xor.enabled() {
            for shard in &mut shards {
                self.xor.process(shard);
            }
        }

        let shard_refs: Vec<&[u8]> = shards.iter().map(|s| s.as_slice()).collect();
        self.fec.encode(&shard_refs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cross-implementation golden vectors from Go kcp-go's
    /// `klauspost/reedsolomon.New(10, 3)`. If the encode matrix ever diverges
    /// from klauspost's `buildMatrix`, FEC recovery of Go-encoded parity yields
    /// garbage and corrupts the KCP stream under packet loss — this test guards
    /// that exact regression (was `(i+1)^j`, incompatible with Go).
    #[test]
    fn test_fec_klauspost_golden() {
        let d = 10usize;
        let mut data: Vec<Vec<u8>> = Vec::new();
        for i in 0..d {
            data.push(vec![
                (i + 1) as u8,
                (i * 7) as u8,
                (i * 13 + 5) as u8,
                (255 - i) as u8,
            ]);
        }
        let refs: Vec<&[u8]> = data.iter().map(|v| v.as_slice()).collect();
        let fec = Fec::new(10, 3);
        let out = fec.encode(&refs);

        // Parity bytes must match klauspost exactly.
        assert_eq!(
            out[10],
            vec![0x45, 0x98, 0x0a, 0xf5],
            "parity[10] != klauspost"
        );
        assert_eq!(
            out[11],
            vec![0xf2, 0xb4, 0x9a, 0xf4],
            "parity[11] != klauspost"
        );
        assert_eq!(
            out[12],
            vec![0x12, 0xdc, 0x0d, 0xf3],
            "parity[12] != klauspost"
        );

        // Reconstruct a lost data shard (drop #3, keep all parity).
        let mut shards: Vec<Option<Vec<u8>>> = out.iter().map(|s| Some(s.clone())).collect();
        let orig3 = shards[3].clone().unwrap();
        shards[3] = None;
        assert!(fec.decode(&mut shards), "decode should reconstruct");
        assert_eq!(
            shards[3].as_ref().unwrap(),
            &orig3,
            "reconstructed shard[3] wrong"
        );
    }

    #[test]
    fn test_xor_roundtrip() {
        let xor = XorBlock::new(b"test-key");
        let mut data = b"hello world".to_vec();
        xor.process(&mut data);
        assert_ne!(data, b"hello world".to_vec());
        xor.process(&mut data);
        assert_eq!(data, b"hello world".to_vec());
    }

    #[test]
    fn test_xor_empty_key() {
        let xor = XorBlock::new(b"");
        let mut data = b"hello world".to_vec();
        xor.process(&mut data);
        assert_eq!(data, b"hello world".to_vec());
    }

    #[test]
    fn test_fec_encode_decode_no_loss() {
        let fec = Fec::new(2, 1); // 2 data + 1 parity
        let input: Vec<&[u8]> = vec![b"abcd", b"efgh"];
        let mut shards: Vec<Option<Vec<u8>>> = fec.encode(&input).into_iter().map(Some).collect();

        // Remove one shard (simulate loss) and reconstruct
        shards[1] = None;
        assert!(fec.decode(&mut shards));
        assert_eq!(shards[1].as_ref().unwrap(), b"efgh");
    }

    #[test]
    fn test_fec_parity_loss_reconstruction() {
        let fec = Fec::new(2, 1);
        let input: Vec<&[u8]> = vec![b"abcd", b"efgh"];
        let mut shards: Vec<Option<Vec<u8>>> = fec.encode(&input).into_iter().map(Some).collect();

        // Remove the parity shard (index 2) — all data shards present, should succeed
        shards[2] = None;
        assert!(fec.decode(&mut shards));
        assert_eq!(shards[0].as_ref().unwrap(), b"abcd");
        assert_eq!(shards[1].as_ref().unwrap(), b"efgh");
    }

    #[test]
    fn test_fec_insufficient_shards() {
        let fec = Fec::new(2, 1);
        let input: Vec<&[u8]> = vec![b"abcd", b"efgh"];
        let mut shards: Vec<Option<Vec<u8>>> = fec.encode(&input).into_iter().map(Some).collect();

        // Remove 2 shards — only 1 remains, need at least 2
        shards[0] = None;
        shards[1] = None;
        assert!(!fec.decode(&mut shards));
    }

    #[test]
    fn test_fec_disabled() {
        let fec = Fec::new(0, 0);
        assert!(!fec.enabled());
        let input: Vec<&[u8]> = vec![b"test"];
        let output = fec.encode(&input);
        assert_eq!(output.len(), 1);
        assert_eq!(output[0], b"test");
    }

    #[test]
    fn test_kcp_compat_session_encode_no_fec_no_xor() {
        // encode_packet with no FEC/XOR is passthrough.
        let session = KcpCompatSession::new(0, 0, b"");
        let data = b"plain kcp data, no encoding at all";
        let encoded = session.encode_packet(data);
        assert_eq!(encoded.len(), 1);
        assert_eq!(encoded[0], data);
    }

    /// The lookup tables must reproduce the bit-serial field multiply exactly —
    /// this is the invariants the wire format depends on.
    #[test]
    fn mul_tables_match_bitwise_field_multiply() {
        for (data, parity) in [(10, 3), (4, 2), (1, 1), (256, 1)] {
            let fec = Fec::new(data, parity);
            assert_eq!(
                fec.mul_tables.len(),
                fec.encode_matrix.len() * data * 256,
                "table length must cover every parity x data coefficient"
            );
            for i in 0..parity.min(fec.encode_matrix.len()) {
                for j in 0..data {
                    let table = fec.mul_table(i, j);
                    let coef = fec.encode_matrix[i][j];
                    for v in 0..=255u8 {
                        assert_eq!(
                            table[v as usize],
                            gf256::mul(coef, v),
                            "data={data} parity={parity} row={i} col={j} v={v}"
                        );
                    }
                }
            }
        }
    }

    /// A disabled codec (0 shards) builds no tables and encodes nothing.
    #[test]
    fn disabled_codec_builds_no_tables() {
        let fec = Fec::new(0, 0);
        assert!(fec.mul_tables.is_empty());
        assert!(fec.nibble_tables.is_empty());
        assert!(fec.encode_matrix.is_empty());
        assert!(!fec.enabled());
    }

    /// The AVX2 kernel itself, called without going through `xor_mul_into`'s
    /// dispatch — so inverting `AVX2_SUPPORTED` or moving the 32-byte threshold
    /// cannot make this pass vacuously. Also pins the `min` contract: a `dst`
    /// longer than `src` must leave its tail untouched.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn avx2_kernel_matches_scalar_table_and_respects_lengths() {
        if !std::arch::is_x86_feature_detected!("avx2") {
            return;
        }
        let fec = Fec::new(10, 3);
        for len in 0..=96usize {
            let src: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            for (pi, di) in [(0usize, 0usize), (2, 7), (1, 9)] {
                let table = fec.mul_table(pi, di);
                let nib = fec.nibble_table(pi, di);
                let lo: &[u8; 16] = nib[..16].try_into().expect("lo half is 16 bytes");
                let hi: &[u8; 16] = nib[16..].try_into().expect("hi half is 16 bytes");
                let mut got = vec![0u8; len];
                // SAFETY: AVX2 verified immediately above; lengths equal.
                unsafe { xor_mul_avx2(&mut got, &src, lo, hi) };
                let mut want = vec![0u8; len];
                for (w, &b) in want.iter_mut().zip(src.iter()) {
                    *w = table[b as usize];
                }
                assert_eq!(got, want, "len {len}, coef row {pi}/{di}");

                // dst longer than src: the tail must not be written. The
                // prefix starts as zeros so it can be compared with `want`.
                let mut long = vec![0u8; len];
                long.extend_from_slice(&[0xAAu8; 5]);
                // SAFETY: as above; `xor_mul_avx2` bounds itself with min().
                unsafe { xor_mul_avx2(&mut long, &src, lo, hi) };
                assert_eq!(&long[..len], &want[..], "prefix len {len}");
                assert!(
                    long[len..].iter().all(|&b| b == 0xAA),
                    "tail written at len {len}"
                );
            }
        }
    }

    /// The vector path must be byte-identical to the scalar table path for
    /// lengths on both sides of the 32-byte vector width, including the odd
    /// tails a 1326-byte KCP segment produces. On targets without AVX2 both
    /// sides of this assertion are the same loop, so it costs nothing there.
    #[test]
    fn vector_encode_matches_scalar_for_all_lengths() {
        for (data, parity) in [(10usize, 3usize), (4, 2), (3, 2)] {
            let fec = Fec::new(data, parity);
            for len in [1usize, 5, 16, 31, 32, 33, 63, 100, 1326, 1327] {
                let shards: Vec<Vec<u8>> = (0..data)
                    .map(|i| (0..len).map(|b| (b * 7 + i * 13) as u8).collect())
                    .collect();
                let refs: Vec<&[u8]> = shards.iter().map(Vec::as_slice).collect();
                let got = fec.encode_parity(&refs);
                for (pi, shard) in got.iter().enumerate() {
                    let mut want = vec![0u8; len];
                    for (di, inp) in refs.iter().enumerate() {
                        let table = fec.mul_table(pi, di);
                        for (w, &b) in want.iter_mut().zip(inp.iter()) {
                            *w ^= table[b as usize];
                        }
                    }
                    assert_eq!(shard, &want, "parity {pi} differs at len {len}");
                }
            }
        }
    }

    /// The table-driven encode must be byte-identical to the reference
    /// bit-serial loop it replaced.
    #[test]
    fn encode_parity_matches_bitwise_reference() {
        for (data, parity, block) in [(10, 3, 1350), (4, 2, 37), (1, 1, 256), (3, 2, 1299)] {
            let fec = Fec::new(data, parity);
            let shards: Vec<Vec<u8>> = (0..data)
                .map(|i: usize| {
                    (0..block)
                        .map(|b: usize| b.wrapping_mul(31).wrapping_add(i * 7) as u8)
                        .collect()
                })
                .collect();
            let refs: Vec<&[u8]> = shards.iter().map(Vec::as_slice).collect();

            let got = fec.encode_parity(&refs);
            for (i, shard) in got.iter().enumerate().take(parity) {
                let mut want = vec![0u8; block];
                for (byte_idx, want_byte) in want.iter_mut().enumerate() {
                    let mut sum = 0u8;
                    for (data_idx, inp) in refs.iter().enumerate() {
                        sum ^= gf256::mul(fec.encode_matrix[i][data_idx], inp[byte_idx]);
                    }
                    *want_byte = sum;
                }
                assert_eq!(
                    shard, &want,
                    "data={data} parity={parity} block={block} row={i}"
                );
            }
        }
    }

    /// Reconstruction through the table path (block >= 256) and the bit-serial
    /// path (block < 256) must agree and recover the missing shard.
    #[test]
    fn reconstruct_recovers_data_shards_on_both_paths() {
        for block in [64usize, 16, 300] {
            let fec = Fec::new(4, 2);
            let data: Vec<Vec<u8>> = (0..4)
                .map(|i: usize| {
                    (0..block)
                        .map(|b| b.wrapping_mul(13).wrapping_add(i * 29) as u8)
                        .collect()
                })
                .collect();
            let refs: Vec<&[u8]> = data.iter().map(Vec::as_slice).collect();
            let parity = fec.encode_parity(&refs);

            // Lose data shards 1 and 3; everything else present.
            let mut shards: Vec<Option<Vec<u8>>> = data.iter().cloned().map(Some).collect();
            shards.push(Some(parity[0].clone()));
            shards.push(Some(parity[1].clone()));
            shards[1] = None;
            shards[3] = None;

            assert!(fec.decode(&mut shards), "block={block} decode failed");
            assert_eq!(shards[1].as_ref(), Some(&data[1]), "block={block} shard 1");
            assert_eq!(shards[3].as_ref(), Some(&data[3]), "block={block} shard 3");
        }
    }
}
