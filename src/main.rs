use base64;
use std::collections::HashMap;
use std::string::FromUtf8Error;
use std::io::{BufRead, BufReader};
use std::fs::File;
use std::fmt;

fn hexstr_to_bytes(hex: Vec<u8>) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(hex.len() / 2);

    for i in 0..(hex.len()/2) {
        let upper = (hex[2*i] as char).to_digit(16).unwrap();
        let lower = (hex[2*i+1] as char).to_digit(16).unwrap();
        bytes.push(((upper << 4) | lower) as u8);
    }

    return bytes;
}

fn bytes_to_hexstr(bytes: Vec<u8>) -> Vec<u8> {
    static CHARS: &'static [u8] = b"0123456789abcdef";
    let mut hexstr = Vec::with_capacity(bytes.len() * 2);

    for b in bytes {
        hexstr.push(CHARS[(b >> 4) as usize]);
        hexstr.push(CHARS[(b & 0x0f) as usize]);
    }

    hexstr
}

fn bytes_to_base64(bytes: Vec<u8>) -> Vec<u8> {
    let mut b64 = Vec::new();

    b64.resize(bytes.len() * 4 / 3 + 4, 0);
    let written = base64::encode_config_slice(&bytes, base64::STANDARD, &mut b64);
    b64.resize(written, 0);
    return b64;
}

fn hexstr_to_base64(hex: Vec<u8>) -> Vec<u8> {
    let bytes = hexstr_to_bytes(hex);
    return bytes_to_base64(bytes);
}

fn fixed_xor(a: Vec<u8>, b: Vec<u8>) -> Option<Vec<u8>> {
    if a.len() != b.len() {
        return None;
    }

    let decoded_a = hexstr_to_bytes(a);
    let decoded_b = hexstr_to_bytes(b);
    let mut xor = Vec::new();
    for i in 0..decoded_a.len() {
        xor.push(decoded_a[i] ^ decoded_b[i]);
    }

    return Some(xor);
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

    for c in cipher.iter() {
        let plain_byte = c ^ key;
        if plain_byte != 10 && (plain_byte < 32 || plain_byte > 122) {
            return Err(HistoError);
        }


        let val = h.entry(plain_byte).or_insert(0);
        *val += 1;
        plaintext.push(plain_byte);
    }

    Ok(Histogram::from_plaintext(h, &plaintext))
}

fn xor_encrypt(key: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut ciphertext = Vec::with_capacity(plaintext.len());
    let mut i = 0;

    while i < plaintext.len() {
        for k in key {
            ciphertext.push(plaintext[i] ^ k);
            i += 1;
            if i == plaintext.len() {
                break;
            }
        }
    }

    ciphertext
}

fn main() {
    println!("Hello, world!");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_to_hexstr() {
        let bytes = vec![0x01, 0x02, 0xab, 0xcd, 0x5f];
        assert_eq!(Vec::from("0102abcd5f"), bytes_to_hexstr(bytes));
    }

    #[test]
    fn test_hex_to_base64() {
        let value:Vec<u8> = Vec::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
        let expected:Vec<u8> = Vec::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
        assert_eq!(hexstr_to_base64(value), expected);
    }

    #[test]
    fn test_xor() {
        let a = Vec::from("1c0111001f010100061a024b53535009181c");
        let b = Vec::from("686974207468652062756c6c277320657965");
        let expected = Vec::from("746865206b696420646f6e277420706c6179");
        assert_eq!(fixed_xor(a, b).unwrap(), hexstr_to_bytes(expected));
    }

    #[test]
    fn test_single_byte_xor() {
        let cipher = Vec::from("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
        let b = hexstr_to_bytes(cipher);
        let mut top_score = 0;
        let mut message = String::new();

        for key in 0..255 {
            let histogram = get_english_histogram(&b, key);
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
                    let cipher = Vec::from(l);
                    let b = hexstr_to_bytes(cipher);

                    for key in 0..255 {
                        let histogram = get_english_histogram(&b, key);
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
        let ciphertext_hex = Vec::from("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");
        let key = Vec::from("ICE");

        assert_eq!(xor_encrypt(&key, &plaintext), hexstr_to_bytes(ciphertext_hex));
    }
}
