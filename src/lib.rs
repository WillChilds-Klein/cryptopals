use std::collections::HashMap;
use std::iter::FromIterator;

// TODO rip out dependencies, re-implement base{16,64} un/parsing
// TODO consolidate to/from methods to take radix as parameter

fn from_base16(input: &str) -> Vec<u8> {
    assert_eq!(0, input.len() % 2);
    let mut bytes = Vec::new();
    for ii in (0..input.len()).step_by(2) {
        bytes.push(u8::from_str_radix(&input[ii..ii+2], 16).unwrap());
    }
    bytes
}

fn to_base16(input: Vec<u8>) -> String {
    hex::encode(input)
}

fn to_base64(input: Vec<u8>) -> String {
    base64::encode(input)
}

fn xor(one: &Vec<u8>, two: &Vec<u8>) -> Vec<u8> {
    assert_eq!(one.len(), two.len());
    let mut output = Vec::new();
    for (x, y) in one.iter().zip(two.iter()) {
        output.push(x ^ y);
    }
    output
}

fn find_single_byte_xor_key(input: &Vec<u8>) -> u8 {
    let mut lowest = (0u8, f32::MAX, 0f32); // value, score, lower-case ratio
    for c in 0..u8::MAX {
        match String::from_utf8(xor(&input, &vec![c; input.len()])) {
            Ok(s) => {
                let score = english_text_score(s.as_str());
                if score < lowest.1 {
                    // NOTE: there will always be 2 keys that result in the same score (with a value
                    //       difference of 32), so assume real sentences tend to have higher ratio
                    //       of lower-case letters. use this heuristic to break the tie.
                    let lower_case_count = s.chars()
                        .filter(char::is_ascii_lowercase)
                        .count();
                    let lower_case_ratio = lower_case_count as f32 /  s.len() as f32;
                    if lower_case_ratio > lowest.2 {
                        lowest = (c, score, lower_case_ratio);
                    }
                }
            },
            Err(_) => {
                continue;
            },
        };
    }
    lowest.0
}

/// Returns a score indicating "englishness" of a string
///
/// Score is effectively distance from standard english alphabetical
/// character frequencies. 0 is highest possible score.
///
/// # Arguments
///
/// * `input` - A string slice to measure the "englishness" of
fn english_text_score(input: &str) -> f32 {
    // @see https://www3.nd.edu/~busiforc/handouts/cryptography/letterfrequencies.html
    let reference_frequencies: HashMap<char,f32> = HashMap::from_iter(vec![
        ('a', 0.084966),
        ('b', 0.020720),
        ('c', 0.045388),
        ('d', 0.033844),
        ('e', 0.111607),
        ('f', 0.018121),
        ('g', 0.024705),
        ('h', 0.030034),
        ('i', 0.075448),
        ('j', 0.001965),
        ('k', 0.011016),
        ('l', 0.054893),
        ('m', 0.030129),
        ('n', 0.066544),
        ('o', 0.071635),
        ('p', 0.031671),
        ('q', 0.001962),
        ('r', 0.075809),
        ('s', 0.057351),
        ('t', 0.069509),
        ('u', 0.036308),
        ('v', 0.010074),
        ('w', 0.012899),
        ('x', 0.002902),
        ('y', 0.017779),
        ('z', 0.002722),
    ]);
    // initialize input character counts
    let mut char_counts: HashMap<char,u32> = HashMap::new();
    for (c, _) in reference_frequencies.iter() {
        char_counts.insert(*c, 0);
    }
    // count the alphabetical chars in the input string, normalized to lower case
    let mut total_char_count = 0;
    for c in input.chars() {
        let cl = c.to_ascii_lowercase();
        if reference_frequencies.contains_key(&cl) {
            char_counts.insert(cl, char_counts.get( & cl).unwrap() + 1);
            total_char_count += 1;
        }
    }
    // calculate the score, building from 0.0
    let mut score = 0f32;
    for (c, _) in reference_frequencies.iter() {
        let reference_frequency = *reference_frequencies.get(&c).unwrap();
        let count = *char_counts.get(&c).unwrap();
        let frequency = count as f32 / total_char_count as f32;
        let distance = (frequency - reference_frequency).abs();
        score += distance;
    }
    score
}

fn repeating_key_xor(message: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    let mut full_key = Vec::new();
    for (ii, _) in message.iter().enumerate() {
        full_key.push(key[ii % key.len()]);
    }
    xor(&message, &full_key)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::*;

    #[test] // Challenge 1.1
    fn test_base16_to_base64() {
        let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let output = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        assert_eq!(output, to_base64(from_base16(input)));
    }

    #[test] // Challenge 1.2
    fn test_xor() {
        let one = "1c0111001f010100061a024b53535009181c";
        let two = "686974207468652062756c6c277320657965";
        let output = "746865206b696420646f6e277420706c6179";
        assert_eq!(output, to_base16(xor(&from_base16(one), &from_base16(two))));
    }

    #[test] // Challenge 1.3
    fn test_find_single_char_xor_decrypt() {
        let ciphertext = from_base16("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
        let key = 'X' as u8;
        let plaintext = String::from_utf8(xor(&ciphertext, &vec![key; ciphertext.len()])).unwrap();
        assert_eq!(key, find_single_byte_xor_key(&ciphertext));
        assert_eq!("Cooking MC's like a pound of bacon", plaintext);
    }

    #[test] // Challenge 1.4
    fn test_find_single_char_xor_decrypt_from_file() {
        let ciphertexts: Vec<Vec<u8>> = fs::read_to_string("tst/data/01_04.txt")
            .expect("Cannot read input data")
            .lines()
            .map(str::trim)
            .map(from_base16)
            .collect();
        let mut lowest = (f32::MAX, 0u8, Vec::new());   // score, key, ciphertext
        for ciphertext in ciphertexts {
            let key = find_single_byte_xor_key(&ciphertext);
            let plaintext = xor(&ciphertext, &vec![key; ciphertext.len()]);
            let score = match String::from_utf8(plaintext) {
                Ok(s) => {
                    english_text_score(&s)
                },
                Err(_) => {
                    continue;
                }
            };
            if score < lowest.0 {
                lowest = (score, key, Vec::from(ciphertext));
            }
        }
        let plaintext = String::from_utf8(
            xor(&lowest.2, &vec![lowest.1; lowest.2.len()])
        ).unwrap();
        assert_eq!(53u8, lowest.1);
        assert_eq!("Now that the party is jumping\n", plaintext);
    }

    #[test] // Challenge 1.5
    fn test_repeating_key_xor_encrypt_decrypt() {
        let expected_ciphertext = from_base16("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");
        let plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal".as_bytes().to_vec();
        let key = "ICE".as_bytes().to_vec();
        let actual_ciphertext = repeating_key_xor(&plaintext, &key);
        assert_eq!(expected_ciphertext, actual_ciphertext);
        let decrypted_plaintext = repeating_key_xor(&actual_ciphertext, &key);
        assert_eq!(plaintext, decrypted_plaintext);
    }
}