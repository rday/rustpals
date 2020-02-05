//! Provides additional functions to assist with cipher operations.
//!
//! # Overview
//!
//! `CryptoByteArray` is a trait that allows easy transitions to and from
//! hex strings and base64 values.
//!
//! For example:
//! ```
//! let hex_string = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
//! let cba_vec = Vec::from_hexstring(&hex_string);
//! ```
//!
//! This trait's methods return new objects containing the results of the operation.

use std::cmp;
use base64;

pub trait CryptoByteArray {

    fn into_hexstring(&self) -> Self;

    fn into_base64(&self) -> Self;

    fn from_hexstring(hexstring: &str) -> Self;

    fn hamming_distance_from(&self, n: Self) -> usize;
}

impl CryptoByteArray for Vec<u8> {

    fn into_hexstring(&self) -> Vec<u8> {
        bytes_to_hexstr(self)
    }

    fn into_base64(&self) -> Vec<u8> {
        bytes_to_base64(&self)
    }

    fn from_hexstring(hexstring: &str) -> Self {
        hexstr_to_bytes(&Vec::from(hexstring))
    }

    fn hamming_distance_from(&self, n: Self) -> usize {
        let min_length = cmp::min(self.len(), n.len());
        let max_len = cmp::max(self.len(), n.len());
        let mut distance = (max_len - min_length) * 8;

        for i in 0..min_length {
            let different_bits = self[i] ^ n[i];
            for j in 0..7 {
                distance += ((different_bits >> j) & 0x01) as usize;
            }
        }

        distance
    }
}

fn hexstr_to_bytes(hex: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(hex.len() / 2);

    for i in 0..(hex.len()/2) {
        let upper = (hex[2*i] as char).to_digit(16).unwrap();
        let lower = (hex[2*i+1] as char).to_digit(16).unwrap();
        bytes.push(((upper << 4) | lower) as u8);
    }

    return bytes;
}

fn bytes_to_hexstr(bytes: &[u8]) -> Vec<u8> {
    static CHARS: &'static [u8] = b"0123456789abcdef";
    let mut hexstr = Vec::with_capacity(bytes.len() * 2);

    for b in bytes {
        hexstr.push(CHARS[(b >> 4) as usize]);
        hexstr.push(CHARS[(b & 0x0f) as usize]);
    }

    hexstr
}

fn bytes_to_base64(bytes: &[u8]) -> Vec<u8> {
    let mut b64 = Vec::new();

    b64.resize(bytes.len() * 4 / 3 + 4, 0);
    let written = base64::encode_config_slice(&bytes, base64::STANDARD, &mut b64);
    b64.resize(written, 0);
    return b64;
}

fn hexstr_to_base64(hex: &[u8]) -> Vec<u8> {
    let bytes = hexstr_to_bytes(hex);
    return bytes_to_base64(&bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_to_hexstr() {
        let bytes = vec![0x01, 0x02, 0xab, 0xcd, 0x5f];
        assert_eq!(Vec::from("0102abcd5f"), bytes_to_hexstr(&bytes));
    }

    #[test]
    fn test_hex_to_base64() {
        let value: Vec<u8> = Vec::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
        let expected: Vec<u8> = Vec::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
        assert_eq!(hexstr_to_base64(&value), expected);
    }

    #[test]
    fn test_hamming_distance() {
        let first = Vec::from("this is a test");
        let second = Vec::from("wokka wokka!!!");

        assert_eq!(first.hamming_distance_from(second), 37);
    }

    #[test]
    fn test_hamming_distance_diff_lengths() {
        let first = Vec::from("this is a test");
        let second = Vec::from("this is");

        assert_eq!(first.hamming_distance_from(second), 56);
    }

}