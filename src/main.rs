use std::collections::HashMap;
use std::string::FromUtf8Error;
use std::io::{BufRead, BufReader};
use std::fs::File;
use std::fmt;

pub mod crypto_byte_array;

use crypto_byte_array::CryptoByteArray;

/// XOR two equal length vectors, returning a new vector.
fn fixed_xor(a: &[u8], b: &[u8]) -> Option<Vec<u8>> {
    if a.len() != b.len() {
        return None;
    }

    let mut xor = Vec::new();
    for i in 0..a.len() {
        xor.push(a[i] ^ b[i]);
    }

    return Some(xor);
}

/// Using a key, XOR encrypt the plaintext.
/// Returns a new vector.
fn xor_encrypt(key: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut ciphertext = Vec::with_capacity(plaintext.len());
    let mut i = 0;

    while i < plaintext.len() {
        ciphertext.push(plaintext[i] ^ key[i % key.len()]);
        i += 1;
    }

    Vec::from(ciphertext)
}

struct Histogram {
    h: HashMap<u8, u32>,
    scores: HashMap<char, u32>,
    data: Vec<u8>,
}

impl Histogram {
    pub fn from_plaintext(h: HashMap<u8, u32>, plaintext: &[u8]) -> Self {
        Histogram {
            h: h,
            scores: [
                ('e', 13), ('t', 12), ('a', 11), ('o', 10), ('i', 9), ('n', 8), (' ', 7),
                ('s', 6), ('h', 5), ('l', 4)
            ].iter().cloned().collect(),
            data: Vec::from(plaintext)
        }
    }

    pub fn get_plaintext(&self) -> Result<String, FromUtf8Error> {
        String::from_utf8(self.data.clone())
    }

    pub fn get_score(&self) -> u32 {
        let mut score = 1;

        for (k, v) in self.h.iter() {
            let ch = *k as char;
            if let Some(s) = self.scores.get(&ch.to_ascii_lowercase()) {
                score += *s* *v;
            }
        }

        return score as u32;
    }
}

#[derive(Debug)]
struct HistoError;
impl fmt::Display for HistoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Decrypted value fell outside of range")
    }
}

fn get_english_histogram(cipher: &[u8], key: u8) -> Result<Histogram, HistoError> {
    let mut plaintext = Vec::new();
    let mut h = HashMap::new();

    for i in 0..cipher.len() {
        let plain_byte = cipher[i] ^ key;
        if plain_byte != 10 && (plain_byte < 32 || plain_byte > 122) {
            return Err(HistoError);
        }


        let val = h.entry(plain_byte).or_insert(0);
        *val += 1;
        plaintext.push(plain_byte);
    }

    Ok(Histogram::from_plaintext(h, &plaintext))
}

fn main() {
    println!("Hello, world!");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor() {
        let a = Vec::from_hexstring("1c0111001f010100061a024b53535009181c");
        let b = Vec::from_hexstring("686974207468652062756c6c277320657965");
        let expected = Vec::from_hexstring("746865206b696420646f6e277420706c6179");
        assert_eq!(fixed_xor(&a, &b).unwrap(), expected);
    }

    #[test]
    fn test_single_byte_xor() {
        let cipher = Vec::from_hexstring("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
        let mut top_score = 0;
        let mut message = String::new();

        for key in 0..255 {
            let histogram = get_english_histogram(&cipher, key);
            match histogram {
                Ok(histogram) => {
                    if histogram.get_score() > top_score {
                        top_score = histogram.get_score();
                        let plaintext = histogram.get_plaintext();
                        match plaintext {
                            Ok(p) => { message = p;  }
                            Err(e) => { println!("Err {}", e); }
                        }
                    }
                }
                Err(_) => { }
            }
        }

        assert_eq!(message, "Cooking MC's like a pound of bacon");
    }

    #[test]
    fn test_find_encrypted_string() {
        let reader = BufReader::new(File::open("data/4.txt").expect("Cannot open 4.txt"));
        let mut top_score = 0;
        let mut message = String::new();

        for line in reader.lines() {
            match line {
                Err(e) => { println!("{}", e); }
                Ok(l) => {
                    let cipher = Vec::from_hexstring(&l);

                    for key in 0..255 {
                        let histogram = get_english_histogram(&cipher, key);
                        match histogram {
                            Ok(histogram) => {
                                if histogram.get_score() > top_score {
                                    top_score = histogram.get_score();
                                    let plaintext = histogram.get_plaintext();
                                    match plaintext {
                                        Ok(p) => { message = p;  }
                                        Err(e) => { println!("Err {}", e); }
                                    }
                                }
                            }
                            Err(_) => {}
                        }
                    }
                }
            }
        }

        assert_eq!("Now that the party is jumping\n", message);
    }

    #[test]
    fn test_repeating_key_xor() {
        let plaintext = Vec::from("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal");
        let key = Vec::from("ICE");
        let ciphertext_hex = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

        assert_eq!(xor_encrypt(&key, &plaintext), Vec::from_hexstring(&ciphertext_hex));
    }
}
