//! Low-level byte encoders the chain adapters share: Base58 (Solana),
//! Keccac-256 and EIP-55 (EVM), Bitcoin script-number and push encoding.
//! Kept dependency-light and covered by known test vectors.

use tiny_keccak::{Hasher, Keccak};

/// Keccak-256 (Ethereum's hash — *not* SHA3-256; the padding differs).
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut k = Keccak::v256();
    let mut out = [0u8; 32];
    k.update(data);
    k.finalize(&mut out);
    out
}

/// The 4-byte function selector for a Solidity signature, e.g.
/// `selector("withdraw(bytes32,bytes32)")`.
pub fn selector(signature: &str) -> [u8; 4] {
    let h = keccak256(signature.as_bytes());
    [h[0], h[1], h[2], h[3]]
}

const B58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Base58 (Bitcoin/Solana alphabet) encoding of a byte string.
pub fn base58(input: &[u8]) -> String {
    let zeros = input.iter().take_while(|&&b| b == 0).count();
    // Big-endian base-58 digits, built by repeated (digits * 256 + byte).
    let mut digits: Vec<u8> = Vec::new();
    for &byte in input {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::with_capacity(zeros + digits.len());
    for _ in 0..zeros {
        out.push('1');
    }
    for &d in digits.iter().rev() {
        out.push(B58[d as usize] as char);
    }
    if out.is_empty() {
        out.push('1');
    }
    out
}

/// An EVM address (20 bytes) as an EIP-55 mixed-case checksummed `0x…` string.
pub fn eip55(addr: &[u8; 20]) -> String {
    let lower = hex::encode(addr);
    let hash = keccak256(lower.as_bytes());
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, c) in lower.chars().enumerate() {
        if c.is_ascii_digit() {
            out.push(c);
        } else {
            // Uppercase the hex letter iff the matching hash nibble is >= 8.
            let nibble = (hash[i / 2] >> (if i % 2 == 0 { 4 } else { 0 })) & 0x0f;
            if nibble >= 8 {
                out.push(c.to_ascii_uppercase());
            } else {
                out.push(c);
            }
        }
    }
    out
}

/// Encode an integer as a Bitcoin script number (`CScriptNum`): minimal
/// little-endian magnitude with an explicit sign bit. Used for the
/// `OP_CHECKLOCKTIMEVERIFY` operand.
pub fn script_num(n: i64) -> Vec<u8> {
    if n == 0 {
        return Vec::new();
    }
    let neg = n < 0;
    let mut abs = n.unsigned_abs();
    let mut out = Vec::new();
    while abs > 0 {
        out.push((abs & 0xff) as u8);
        abs >>= 8;
    }
    // If the top bit of the most-significant byte is set, it would be read as
    // the sign bit, so append a byte carrying the real sign.
    if out.last().unwrap() & 0x80 != 0 {
        out.push(if neg { 0x80 } else { 0x00 });
    } else if neg {
        *out.last_mut().unwrap() |= 0x80;
    }
    out
}

/// Append a canonical data push (`OP_PUSHBYTES_n <data>`) to a Bitcoin script.
/// Only lengths that fit a single-byte push (≤ 75) are needed for HTLC scripts.
pub fn push_data(script: &mut Vec<u8>, data: &[u8]) {
    assert!(data.len() <= 75, "push_data only handles OP_PUSHBYTES_1..=75");
    script.push(data.len() as u8);
    script.extend_from_slice(data);
}

/// Left-pad a byte string to a 32-byte big-endian ABI word.
pub fn abi_word(bytes: &[u8]) -> [u8; 32] {
    assert!(bytes.len() <= 32);
    let mut w = [0u8; 32];
    w[32 - bytes.len()..].copy_from_slice(bytes);
    w
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base58_all_zero_pubkey() {
        // The 32-byte zero pubkey is the canonical Solana "default" address.
        assert_eq!(base58(&[0u8; 32]), "1".repeat(32));
    }

    #[test]
    fn base58_known_vector() {
        // "hello world" → known Base58 value.
        assert_eq!(base58(b"hello world"), "StV1DL6CwTryKyV");
    }

    #[test]
    fn keccak_empty() {
        // Keccak-256("") — the canonical empty-input digest.
        assert_eq!(
            hex::encode(keccak256(b"")),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    #[test]
    fn selector_transfer() {
        // The ERC-20 transfer selector is the textbook Keccak selector check.
        assert_eq!(hex::encode(selector("transfer(address,uint256)")), "a9059cbb");
    }

    #[test]
    fn eip55_checksum_vector() {
        // A canonical EIP-55 test address.
        let mut a = [0u8; 20];
        a.copy_from_slice(&hex::decode("5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed").unwrap());
        assert_eq!(eip55(&a), "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
    }

    #[test]
    fn script_num_locktime() {
        // 800000 = 0x0C3500 → little-endian minimal, no sign byte needed.
        assert_eq!(script_num(800_000), vec![0x00, 0x35, 0x0c]);
        assert_eq!(script_num(0), Vec::<u8>::new());
        // 0x80 needs a sign byte so it is not read as negative zero.
        assert_eq!(script_num(128), vec![0x80, 0x00]);
    }
}
