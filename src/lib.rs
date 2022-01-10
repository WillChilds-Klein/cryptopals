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

// Challenge 1.2
fn xor(one: &Vec<u8>, two: &Vec<u8>) -> Vec<u8> {
    assert_eq!(one.len(), two.len());
    let mut output = Vec::new();
    for (x, y) in one.iter().zip(two.iter()) {
        output.push(x ^ y);
    }
    output
}

// Challenge 1.3
fn find_single_byte_xor_key(input: Vec<u8>) -> u8 {
    let mut lowest = (0u8, f32::MAX);
    for c in 0..u8::MAX {
        match String::from_utf8(xor(&input, &vec![c; input.len()])) {
            Ok(s) => {
                let score = english_text_score(s.as_str());
                if score < lowest.1 {
                    lowest = (c, score);
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
    let mut score: f32 = 0.0;
    for (c, _) in reference_frequencies.iter() {
        let reference_frequency = *reference_frequencies.get(&c).unwrap();
        let count = *char_counts.get(&c).unwrap();
        let frequency = count as f32 / total_char_count as f32;
        let distance = (frequency - reference_frequency).abs();
        score += distance;
    }
    score
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn test_base16_to_base64() {
        let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let output = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        assert_eq!(output, to_base64(from_base16(input)));
    }

    #[test]
    fn test_xor() {
        let one = "1c0111001f010100061a024b53535009181c";
        let two = "686974207468652062756c6c277320657965";
        let output = "746865206b696420646f6e277420706c6179";
        assert_eq!(output, to_base16(xor(&from_base16(one), &from_base16(two))));
    }

    #[test]
    fn test_find_single_char_xor_decrypt() {
        let ciphertext = from_base16("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
        assert_eq!('X', find_single_byte_xor_key(ciphertext) as char);
    }
}