//! Radix-P, the 512 bit ARX permutation.
//!
//! The state is a 4x4 matrix of 32 bit words, stored row by row. One round is
//! AddConstant (s0 ^= RC[i]), ColumnMix (G on the four columns) and ShiftRows
//! (row r rotated left by r words). Twenty rounds.

pub const WORDS: usize = 16;
pub const ROUNDS: usize = 20;

pub type State = [u32; WORDS];

/// Rotation amounts of G.
const R1: u32 = 25;
const R2: u32 = 11;
const R3: u32 = 16;
const R4: u32 = 6;

/// floor(sqrt(p) * 2^32) mod 2^32 for the first 20 primes.
pub const RC: [u32; ROUNDS] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    0xcbbb9d5d, 0x629a292a, 0x9159015a, 0x152fecd8, 0x67332667, 0x8eb44a87, 0xdb0c2e0d, 0x47b5481d,
    0xae5f9156, 0xcf6c85d3, 0x2f73477d, 0x6d1826ca,
];

/// Constant indices and rotations keep the whole state in registers; there
/// are no branches or table lookups that depend on the data.
pub fn permute(s: &mut State) {
    macro_rules! g {
        ($x:ident, $a:literal, $b:literal, $c:literal, $d:literal) => {
            $x[$a] = $x[$a].wrapping_add($x[$b]);
            $x[$d] = ($x[$d] ^ $x[$a]).rotate_left(R1);
            $x[$c] = $x[$c].wrapping_add($x[$d]);
            $x[$b] = ($x[$b] ^ $x[$c]).rotate_left(R2);
            $x[$a] = $x[$a].wrapping_add($x[$b]);
            $x[$d] = ($x[$d] ^ $x[$a]).rotate_left(R3);
            $x[$c] = $x[$c].wrapping_add($x[$d]);
            $x[$b] = ($x[$b] ^ $x[$c]).rotate_left(R4);
        };
    }
    let mut x = *s;
    for rc in RC {
        x[0] ^= rc;
        g!(x, 0, 4, 8, 12);
        g!(x, 1, 5, 9, 13);
        g!(x, 2, 6, 10, 14);
        g!(x, 3, 7, 11, 15);
        x = [
            x[0], x[1], x[2], x[3], //
            x[5], x[6], x[7], x[4], //
            x[10], x[11], x[8], x[9], //
            x[15], x[12], x[13], x[14],
        ];
    }
    *s = x;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Integer square root by bisection (u128::isqrt needs a newer Rust);
    /// enough for the inputs here, which stay below 2^71.
    fn isqrt(n: u128) -> u128 {
        let (mut lo, mut hi) = (0u128, 1u128 << 40);
        while lo < hi {
            let mid = (lo + hi).div_ceil(2);
            if mid * mid <= n {
                lo = mid;
            } else {
                hi = mid - 1;
            }
        }
        lo
    }

    #[test]
    fn round_constants_are_sqrt_of_primes() {
        let primes = [
            2u128, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
        ];
        for (p, rc) in primes.iter().zip(RC) {
            assert_eq!(isqrt(p << 64) as u32, rc, "p = {p}");
        }
    }

    #[test]
    fn known_answers() {
        let mut zero = [0u32; WORDS];
        permute(&mut zero);
        assert_eq!(
            zero,
            [
                0x4c484def, 0xf72e49a7, 0xb5d25217, 0x3675bfe5, 0x7dfdf716, 0xdc183a42, 0x01efff42,
                0x63f7ad5b, 0x4ca1e09a, 0x3b7cfd29, 0x33a449b9, 0x79baf93e, 0xb9180e92, 0x32f74d8f,
                0x1c3b1b7c, 0x9081f132,
            ]
        );
        let mut count: State = std::array::from_fn(|i| i as u32);
        permute(&mut count);
        assert_eq!(
            count,
            [
                0x0f3b67d3, 0xf503d701, 0xc2b4f88c, 0xd2f8b103, 0xdb842eeb, 0x9ff75169, 0xfd926fed,
                0x144afd7c, 0x186bf617, 0xa9f71df9, 0x15b57a49, 0x5a650b63, 0xbc6896ea, 0x89e4f088,
                0xe472daf1, 0x82287f91,
            ]
        );
    }
}
