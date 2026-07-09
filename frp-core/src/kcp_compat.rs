//! KCP compatibility layer matching Go kcp-go wire format.
//!
//! Go's kcp-go wraps raw KCP with two layers:
//! 1. XOR encryption (repeating-key)
//! 2. FEC — Reed-Solomon forward error correction over GF(2^8)
//!
//! This module provides equivalent encode/decode for Go↔Rust KCP compatibility.

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
    #[allow(dead_code)]
    total_shards: usize,
    /// Pre-computed Vandermonde encoding matrix rows for parity shards.
    encode_matrix: Vec<Vec<u8>>,
}

impl Fec {
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
        let total_shards = data_shards + parity_shards;
        let encode_matrix = if data_shards > 0 && parity_shards > 0 {
            // Vandermonde: vm[r][c] = r^c (r from 0), matching klauspost galExp.
            let vm: Vec<Vec<u8>> = (0..total_shards)
                .map(|r| (0..data_shards).map(|c| gf256::pow(r as u8, c as u32)).collect())
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
        Self {
            data_shards,
            parity_shards,
            total_shards,
            encode_matrix,
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
            for (byte_idx, parity_byte) in parity.iter_mut().enumerate() {
                let mut sum = 0u8;
                for (data_idx, inp) in input.iter().enumerate() {
                    sum ^= gf256::mul(self.encode_matrix[i][data_idx], inp[byte_idx]);
                }
                *parity_byte = sum;
            }
            output.push(parity);
        }
        output
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
        let block_size = shards
            .iter()
            .find_map(|s| s.as_ref().map(|v| v.len()))
            .unwrap_or(0);
        if block_size == 0 {
            return false;
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
            for (byte_idx, rec_byte) in reconstructed.iter_mut().enumerate() {
                let mut sum = 0u8;
                for (row, &pres_idx) in selected.iter().enumerate() {
                    let val = shards[pres_idx].as_ref().unwrap()[byte_idx];
                    sum ^= gf256::mul(inv_row[row], val);
                }
                *rec_byte = sum;
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
        Self {
            key: key.to_vec(),
        }
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
/// 3. Call `decode_packets()` on received raw KCP data
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

    /// Decode received packets, reconstructing original data.
    ///
    /// `shards`: received shards (may have gaps/fewer than total).
    /// Returns reconstructed data bytes.
    pub fn decode_packets(&self, shards: &mut [Option<Vec<u8>>]) -> Option<Vec<u8>> {
        if !self.fec.enabled() {
            // No FEC: just return the first shard (should be only one)
            let mut data = shards[0].take()?;
            if self.xor.enabled() {
                self.xor.process(&mut data);
            }
            return Some(data);
        }

        if !self.fec.decode(shards) {
            return None;
        }

        // Apply XOR to each data shard individually (matching per-shard XOR in encode)
        // This must happen BEFORE reassembly because each shard starts from key[0].
        if self.xor.enabled() {
            for data in shards.iter_mut().take(self.fec.data_shards).flatten() {
                self.xor.process(data);
            }
        }

        // Reassemble from data shards
        let block_size = shards[0].as_ref()?.len();
        let mut data = Vec::with_capacity(block_size * self.fec.data_shards);
        for s in shards.iter().take(self.fec.data_shards).flatten() {
            data.extend_from_slice(s);
        }

        // Remove padding (trailing zeros)
        while data.last() == Some(&0) {
            data.pop();
        }

        Some(data)
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
        assert_eq!(out[10], vec![0x45, 0x98, 0x0a, 0xf5], "parity[10] != klauspost");
        assert_eq!(out[11], vec![0xf2, 0xb4, 0x9a, 0xf4], "parity[11] != klauspost");
        assert_eq!(out[12], vec![0x12, 0xdc, 0x0d, 0xf3], "parity[12] != klauspost");

        // Reconstruct a lost data shard (drop #3, keep all parity).
        let mut shards: Vec<Option<Vec<u8>>> = out.iter().map(|s| Some(s.clone())).collect();
        let orig3 = shards[3].clone().unwrap();
        shards[3] = None;
        assert!(fec.decode(&mut shards), "decode should reconstruct");
        assert_eq!(shards[3].as_ref().unwrap(), &orig3, "reconstructed shard[3] wrong");
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
    fn test_kcp_compat_session_roundtrip() {
        let session = KcpCompatSession::new(2, 1, b"my-xor-key");
        let data = b"hello kcp compat test message!";

        let encoded = session.encode_packet(data);
        assert_eq!(encoded.len(), 3); // 2 data + 1 parity

        // Simulate all shards received
        let mut received: Vec<Option<Vec<u8>>> = encoded.into_iter().map(Some).collect();
        let decoded = session.decode_packets(&mut received).unwrap();
        assert_eq!(&decoded[..data.len()], data);
    }

    #[test]
    fn test_kcp_compat_session_roundtrip_with_loss() {
        let session = KcpCompatSession::new(3, 2, b""); // 3 data + 2 parity, no XOR
        let data = b"this is a test message for FEC recovery with data loss";

        let encoded = session.encode_packet(data);
        assert_eq!(encoded.len(), 5);

        // Simulate loss of 2 data shards — should recover from remaining 1 data + 2 parity
        let mut received: Vec<Option<Vec<u8>>> = encoded.into_iter().map(Some).collect();
        received[0] = None;
        received[1] = None;
        let decoded = session.decode_packets(&mut received).unwrap();
        assert_eq!(&decoded[..data.len()], data);
    }

    #[test]
    fn test_kcp_compat_session_no_fec() {
        let session = KcpCompatSession::new(0, 0, b"xor-key");
        let data = b"test data";
        let encoded = session.encode_packet(data);
        assert_eq!(encoded.len(), 1);
        let mut received: Vec<Option<Vec<u8>>> = encoded.into_iter().map(Some).collect();
        let decoded = session.decode_packets(&mut received).unwrap();
        assert_eq!(&decoded[..data.len()], data);
    }

    #[test]
    fn test_kcp_compat_session_no_xor_no_fec() {
        let session = KcpCompatSession::new(0, 0, b"");
        let data = b"plain kcp data, no encoding at all";
        let encoded = session.encode_packet(data);
        assert_eq!(encoded.len(), 1);
        assert_eq!(encoded[0], data);

        let mut received: Vec<Option<Vec<u8>>> = encoded.into_iter().map(Some).collect();
        let decoded = session.decode_packets(&mut received).unwrap();
        assert_eq!(decoded, data);
    }
}
