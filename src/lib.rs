use std::collections::HashMap;
use std::iter::FromIterator;

// TODO rip out encoding dependencies, re-implement base{16,64} un/parsing
// TODO consolidate to/from methods to take radix as parameter
// TODO take a stab at implementing aes block cipher (ECB mode for simplicity?)
// TODO break out separate modules per challenge set, factor out various util modules
// TODO write README with explanation that performance/low-copy is an explicit non-goal, preferring simplicity/clarity
// TODO organize tests such that name corresponds to challenge # where appropriate, remove extraneous comments

fn from_base16(input: &str) -> Vec<u8> {
    assert_eq!(0, input.len() % 2);
    let mut bytes = Vec::new();
    for ii in (0..input.len()).step_by(2) {
        bytes.push(u8::from_str_radix(&input[ii..ii + 2], 16).unwrap());
    }
    bytes
}

fn to_base16(input: &Vec<u8>) -> String {
    hex::encode(input)
}

fn from_base64(input: &str) -> Vec<u8> {
    match base64::decode(input) {
        Ok(s) => s,
        Err(e) => panic!("{}", e),
    }
}

fn to_base64(input: &Vec<u8>) -> String {
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
                    //       difference of 32, i.e. the 2^5 bit is either set or not set), so assume
                    //       real sentences tend to have higher ratio of lower-case letters. use this
                    //       heuristic to break the tie.
                    let lower_case_count = s
                        .chars()
                        .filter(|c| c.is_ascii_lowercase() || *c == ' ')
                        .count();
                    let lower_case_ratio = lower_case_count as f32 / s.len() as f32;
                    if lower_case_ratio > lowest.2 {
                        lowest = (c, score, lower_case_ratio);
                    }
                }
            }
            Err(_) => {
                continue;
            }
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
    // @see https://web.archive.org/web/20170918020907/http://www.data-compression.com/english.html
    let reference_frequencies: HashMap<char, f32> = HashMap::from_iter(vec![
        ('a', 0.0651738),
        ('b', 0.0124248),
        ('c', 0.0217339),
        ('d', 0.0349835),
        ('e', 0.1041442),
        ('f', 0.0197881),
        ('g', 0.0158610),
        ('h', 0.0492888),
        ('i', 0.0558094),
        ('j', 0.0009033),
        ('k', 0.0050529),
        ('l', 0.0331490),
        ('m', 0.0202124),
        ('n', 0.0564513),
        ('o', 0.0596302),
        ('p', 0.0137645),
        ('q', 0.0008606),
        ('r', 0.0497563),
        ('s', 0.0515760),
        ('t', 0.0729357),
        ('u', 0.0225134),
        ('v', 0.0082903),
        ('w', 0.0171272),
        ('x', 0.0013692),
        ('y', 0.0145984),
        ('z', 0.0007836),
        (' ', 0.1918182),
    ]);
    // initialize input character counts
    let mut char_counts: HashMap<char, u32> = HashMap::new();
    for (c, _) in reference_frequencies.iter() {
        char_counts.insert(*c, 0);
    }
    // count the alphabetical chars in the input string, normalized to lower case
    let mut total_char_count = 0;
    for c in input.chars() {
        let cl = c.to_ascii_lowercase();
        if reference_frequencies.contains_key(&cl) {
            char_counts.insert(cl, char_counts.get(&cl).unwrap() + 1);
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

fn repeating_key_xor(input: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    let mut full_key = Vec::new();
    for (ii, _) in input.iter().enumerate() {
        full_key.push(key[ii % key.len()]);
    }
    xor(&input, &full_key)
}

fn hamming_distance(one: &Vec<u8>, two: &Vec<u8>) -> u64 {
    assert_eq!(one.len(), two.len());
    let mut distance = 0u64;
    for (x, y) in one.iter().zip(two.iter()) {
        let mask = x ^ y;
        for ii in 0..8 {
            distance += ((mask >> ii) & 1) as u64;
        }
    }
    distance
}

fn find_keysize(ciphertext: &Vec<u8>) -> usize {
    let mut leader = (0, f64::MAX); // value, avg. distance
    for candidate_keysize in 2..64 {
        let pad_size = candidate_keysize - (ciphertext.len() % candidate_keysize);
        let mut ciphertext_padded = ciphertext.clone();
        ciphertext_padded.extend(vec![0u8; pad_size]);
        assert_eq!(0, ciphertext_padded.len() % candidate_keysize);
        // NOTE: 2D vector for convenience, vector of slices would be faster
        let chunks: Vec<Vec<u8>> = ciphertext_padded
            .chunks_exact(candidate_keysize)
            .map(|s| s.into())
            .collect();
        // TODO: justify this narsty quadratic behavior
        let mut distances: Vec<u64> = Vec::new();
        for ii in 0..chunks.len() {
            for jj in ii + 1..chunks.len() {
                distances.push(hamming_distance(&chunks[ii], &chunks[jj]));
            }
        }
        let normalized_avg_distance = distances.iter().sum::<u64>() as f64
            / distances.len() as f64
            / candidate_keysize as f64;
        if normalized_avg_distance < leader.1 {
            leader = (candidate_keysize, normalized_avg_distance);
        }
    }
    leader.0
}

fn transpose(input: &Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let width = input.len();
    let height = input.get(0).unwrap().len(); // TODO handle 0-size case
    let mut output: Vec<Vec<u8>> = vec![vec![0u8; width]; height];
    for ii in 0..width {
        for jj in 0..height {
            output[jj][ii] = input[ii][jj];
        }
    }
    output
}

fn find_xor_key(ciphertext: &Vec<u8>) -> Vec<u8> {
    let keysize = find_keysize(ciphertext);
    let pad_size = keysize - (ciphertext.len() % keysize);
    let mut ciphertext_padded = ciphertext.clone();
    ciphertext_padded.extend(vec![0u8; pad_size]);
    assert_eq!(0, ciphertext_padded.len() % keysize);
    let transposed_blocks = transpose(
        &ciphertext_padded
            .chunks_exact(keysize)
            .map(|s| s.into())
            .collect(),
    );
    let mut key: Vec<u8> = Vec::new();
    assert_eq!(keysize, transposed_blocks.len());
    for ii in 0..keysize {
        key.push(find_single_byte_xor_key(&transposed_blocks[ii]));
    }
    key
}

fn decrypt_xor(ciphertext: &Vec<u8>) -> Vec<u8> {
    let key = find_xor_key(ciphertext);
    repeating_key_xor(&ciphertext, &key)
}

/// @see https://datatracker.ietf.org/doc/html/rfc2315#section-10.3
///
/// > For such algorithms, the method shall be to pad the input at the
/// > trailing end with k - (l mod k) octets all having value k -
/// > (l mod k), where l is the length of the input.
fn pkcs7_pad(input: &Vec<u8>, block_size: usize) -> Vec<u8> {
    let mut output = input.clone();
    let pad_size = block_size - (input.len() % block_size);
    assert!(pad_size <= block_size);
    output.append(&mut vec![pad_size as u8; pad_size]);
    output
}

fn pkcs7_unpad(input: &Vec<u8>) -> Vec<u8> {
    let mut output = input.clone();
    let pad_size = output[output.len() - 1];
    output.truncate(input.len() - pad_size as usize);
    output
}

fn aes_128_ecb_decrypt(ciphertext: &Vec<u8>, key: &Vec<u8>, do_pad: bool) -> Option<Vec<u8>> {
    match aes_128_ecb_common(ciphertext, key, openssl::symm::Mode::Decrypt) {
        Some(s) => Some(if do_pad { pkcs7_unpad(&s) } else { s }),
        None => None,
    }
}

fn aes_128_ecb_encrypt(input_plaintext: &Vec<u8>, key: &Vec<u8>, do_pad: bool) -> Option<Vec<u8>> {
    let block_size = openssl::symm::Cipher::aes_128_ecb().block_size();
    let plaintext = if do_pad {
        pkcs7_pad(&input_plaintext, block_size)
    } else {
        input_plaintext.clone()
    };
    aes_128_ecb_common(&plaintext, key, openssl::symm::Mode::Encrypt)
}

fn aes_128_ecb_common(data: &Vec<u8>, key: &Vec<u8>, mode: openssl::symm::Mode) -> Option<Vec<u8>> {
    let cipher = openssl::symm::Cipher::aes_128_ecb();
    let block_size = cipher.block_size();
    let mut output = Vec::new();
    let block_buffer = &mut vec![0u8; 2 * block_size][..]; // openssl wrapper requires over-sized output buffer
    for ii in 0..(data.len() / block_size) + 1 {
        let block_start = block_size * ii;
        let block_end = std::cmp::min(block_start + block_size, data.len());
        let block = data[block_start..block_end].to_vec();

        // NOTE: need to create new Crypter for each block due to openssl crate's limitations. they don't
        //       expose a "reset" method on the Crypter context. also, we're using lower-level Crypter instead
        //       of Cipher because the latter doesn't expose padding configuration, turns padding on by default, and
        //       pads to 32 bytes (which is odd given that AES block size is 16 bytes). maybe this would help:
        //       https://github.com/sfackler/rust-openssl/issues/1156
        let mut crypter = openssl::symm::Crypter::new(cipher, mode, key, None).unwrap();
        crypter.pad(false);

        let count = crypter.update(&block, block_buffer).unwrap();
        let rest = crypter.finalize(&mut block_buffer[count..]).unwrap();
        output.append(&mut block_buffer[..(count + rest)].to_vec());
    }
    Some(output)
}

// TODO clean up the Option interface -- move to Result<Vec<u8>,MyErr> where MyErr is customer error?

fn aes_128_cbc_decrypt(
    ciphertext: &Vec<u8>,
    key: &Vec<u8>,
    iv: &Vec<u8>,
    do_pad: bool,
) -> Option<Vec<u8>> {
    let block_size = openssl::symm::Cipher::aes_128_cbc().block_size();
    assert_eq!(block_size, key.len());
    assert_eq!(0, ciphertext.len() % block_size);
    assert_eq!(block_size, iv.len());
    let mut prev_block = iv.clone();
    let mut plaintext = Vec::new();
    for ii in 0..(ciphertext.len() / block_size) {
        let block_start = block_size * ii;
        let block_end = block_start + block_size;
        let block = &ciphertext[block_start..block_end].to_vec();
        match aes_128_ecb_decrypt(&block, key, false) {
            Some(s) => {
                plaintext.extend(xor(&s, &prev_block));
                prev_block.copy_from_slice(&ciphertext[block_start..block_end]);
            }
            None => return None,
        }
    }
    Some(if do_pad {
        pkcs7_unpad(&plaintext)
    } else {
        plaintext
    })
}

fn aes_128_cbc_encrypt(
    input_plaintext: &Vec<u8>,
    key: &Vec<u8>,
    iv: &Vec<u8>,
    do_pad: bool,
) -> Option<Vec<u8>> {
    let block_size = openssl::symm::Cipher::aes_128_cbc().block_size();
    assert_eq!(block_size, key.len());
    assert_eq!(block_size, iv.len());
    let plaintext = if do_pad {
        pkcs7_pad(&input_plaintext, block_size)
    } else {
        input_plaintext.clone()
    };
    assert_eq!(0, plaintext.len() % block_size);
    assert_eq!(block_size, key.len());
    let mut prev_block = iv.clone();
    let mut ciphertext = Vec::new();
    for ii in 0..(plaintext.len() / block_size) {
        let block_start = block_size * ii;
        let block_end = block_start + block_size;
        let block = &plaintext[block_start..block_end].to_vec();
        match aes_128_ecb_encrypt(&xor(&block, &prev_block), key, false) {
            Some(s) => {
                ciphertext.extend(&s);
                prev_block.copy_from_slice(&ciphertext[block_start..block_end]);
            }
            None => return None,
        }
    }
    Some(ciphertext)
}

#[cfg(test)]
mod tests {
    use rand::Rng;
    use std::fs;

    use crate::*;

    #[test] // Challenge 1
    fn test_base16_to_base64() {
        let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let output = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        assert_eq!(output, to_base64(&from_base16(input)));
    }

    #[test] // Challenge 2
    fn test_xor() {
        let one = "1c0111001f010100061a024b53535009181c";
        let two = "686974207468652062756c6c277320657965";
        let output = "746865206b696420646f6e277420706c6179";
        assert_eq!(
            output,
            to_base16(&xor(&from_base16(one), &from_base16(two)))
        );
    }

    #[test] // Challenge 3
    fn test_find_single_char_xor_decrypt() {
        let ciphertext =
            from_base16("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
        let key = 'X' as u8;
        let plaintext = String::from_utf8(xor(&ciphertext, &vec![key; ciphertext.len()])).unwrap();
        assert_eq!(key, find_single_byte_xor_key(&ciphertext));
        assert_eq!("Cooking MC's like a pound of bacon", plaintext);
    }

    #[test] // Challenge 4
    fn test_find_single_char_xor_decrypt_from_file() {
        let ciphertexts: Vec<Vec<u8>> = fs::read_to_string("tst/data/04.txt")
            .expect("Cannot read input data")
            .lines()
            .map(str::trim)
            .map(from_base16)
            .collect();
        let mut lowest = (f32::MAX, 0u8, Vec::new()); // score, key, ciphertext
        for ciphertext in ciphertexts {
            let key = find_single_byte_xor_key(&ciphertext);
            let plaintext = xor(&ciphertext, &vec![key; ciphertext.len()]);
            let score = match String::from_utf8(plaintext) {
                Ok(s) => english_text_score(&s),
                Err(_) => {
                    continue;
                }
            };
            if score < lowest.0 {
                lowest = (score, key, Vec::from(ciphertext));
            }
        }
        let plaintext = String::from_utf8(xor(&lowest.2, &vec![lowest.1; lowest.2.len()])).unwrap();
        assert_eq!(53u8, lowest.1);
        assert_eq!("Now that the party is jumping\n", plaintext);
    }

    #[test] // Challenge 5
    fn test_repeating_key_xor_encrypt_decrypt() {
        let expected_ciphertext = from_base16("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");
        let plaintext =
            "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
                .as_bytes()
                .to_vec();
        let key = "ICE".as_bytes().to_vec();
        let actual_ciphertext = repeating_key_xor(&plaintext, &key);
        assert_eq!(expected_ciphertext, actual_ciphertext);
        let decrypted_plaintext = repeating_key_xor(&actual_ciphertext, &key);
        assert_eq!(plaintext, decrypted_plaintext);
    }

    #[test] // Challenge 6
    fn test_hamming_distance() {
        let one = "this is a test".as_bytes().to_vec();
        let two = "wokka wokka!!!".as_bytes().to_vec();
        assert_eq!(37, hamming_distance(&one, &two));
    }

    #[test] // Challenge 6
    fn test_find_keysize() {
        let ciphertext: Vec<u8> = from_base64(
            fs::read_to_string("tst/data/06.txt")
                .expect("Cannot read input data")
                .replace('\n', "")
                .as_str(),
        );
        assert_eq!(29, find_keysize(&ciphertext));
        let plaintext = decrypt_xor(&ciphertext);
        let prelude = "I'm back and I'm ringin' the bell";
        assert_eq!(
            prelude,
            String::from_utf8(plaintext[0..prelude.len()].to_vec()).unwrap()
        );
    }

    #[test] // Challenge 7
    fn test_aes_128_ecb_decrypt() {
        let ciphertext: Vec<u8> = from_base64(
            fs::read_to_string("tst/data/07.txt")
                .expect("Cannot read input data")
                .replace('\n', "")
                .as_str(),
        );
        let key = "YELLOW SUBMARINE";
        let plaintext = aes_128_ecb_decrypt(&ciphertext, &key.as_bytes().to_vec(), false).unwrap();
        let prelude = "I'm back and I'm ringin' the bell";
        assert_eq!(
            prelude,
            String::from_utf8(plaintext[0..prelude.len()].to_vec()).unwrap()
        );
    }

    #[test] // Challenge 8
    fn test_detect_ecb() {
        // basically, we just look for any entry with repeated 16-byte chunks.
        let ciphertexts: Vec<Vec<u8>> = fs::read_to_string("tst/data/08.txt")
            .expect("Cannot read input data")
            .lines()
            .map(from_base16)
            .collect();
        let mut repeated_chunk_counts = Vec::new();
        for ciphertext in ciphertexts {
            let mut repeated_chunks = HashMap::new();
            ciphertext
                .chunks_exact(16)
                .for_each(|chunk| *repeated_chunks.entry(chunk.to_vec()).or_insert(0) += 1);
            repeated_chunks.retain(|_, v| *v > 1);
            if repeated_chunks.len() > 0 {
                repeated_chunk_counts.push((ciphertext.clone(), repeated_chunks));
            }
        }
        assert_eq!(1, repeated_chunk_counts.len());
        assert_eq!(
            "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a",
            to_base16(&repeated_chunk_counts.get(0).unwrap().0)
        );
    }

    #[test]
    fn test_pkcs7_pad_unpad_symmetry() {
        let max_block_size = 64;
        let max_message_size = 1024;
        for ii in 0..max_message_size + 1 {
            for bs in (8..max_block_size + 1).step_by(8) {
                let test_data = vec![0xff; ii];
                let unpadded = test_data[0..ii].to_vec();
                let padded = pkcs7_pad(&unpadded, bs);
                // assert block alignment
                assert_eq!(0, padded.len() % bs);
                // even in block-aligned case, assert that we add a block of bytes with value of blocksize
                assert_ne!(padded.len(), unpadded.len());
                if padded[padded.len() - 1] as usize == bs {
                    assert_eq!(unpadded.len() + bs, padded.len());
                    for pad_byte in padded[unpadded.len()..].to_vec() {
                        assert_eq!(bs as u8, pad_byte);
                    }
                }
                let pad_start_idx = unpadded.len();
                for jj in 0..pad_start_idx {
                    assert_eq!(unpadded[jj], padded[jj]);
                }
                let mut pad_count = 0;
                for _ in pad_start_idx..padded.len() {
                    pad_count += 1;
                }
                if unpadded.len() != padded.len() {
                    assert_eq!(padded[padded.len() - 1], pad_count as u8);
                } else {
                    assert_eq!(0, pad_count);
                }
                assert_eq!(unpadded, pkcs7_unpad(&padded));
            }
        }
    }

    #[test] // Challenge 9
    fn test_challenge_09() {
        assert_eq!(
            b"YELLOW SUBMARINE\x04\x04\x04\x04".to_vec(),
            pkcs7_pad(&"YELLOW SUBMARINE".as_bytes().to_vec(), 20)
        );
    }

    #[test]
    fn test_aes_128_ebc_crypt_symmetry() {
        let plaintext = "Stop your messing around; Better think of your future, Time to straighten right out, Creating problems in town.".as_bytes().to_vec();
        let key = "A Message 2 Rudy".as_bytes().to_vec();
        let ciphertext = aes_128_ecb_encrypt(&plaintext, &key, true).unwrap();
        let decrypted_plaintext = aes_128_ecb_decrypt(&ciphertext, &key, true).unwrap();
        assert_eq!(plaintext, decrypted_plaintext);
    }

    #[test]
    fn test_aes_128_cbc_crypt_symmetry() {
        let plaintext = "Stop your messing around; Better think of your future, Time to straighten right out, Creating problems in town.".as_bytes().to_vec();
        let key = "A Message 2 Rudy".as_bytes().to_vec(); // NOTE: needs to be same len as block size
        let mut rng = rand::thread_rng();
        let iv = (0..key.len()).map(|_| rng.gen::<u8>()).collect();
        let ciphertext = aes_128_cbc_encrypt(&plaintext, &key, &iv, true).unwrap();
        let decrypted_plaintext = aes_128_cbc_decrypt(&ciphertext, &key, &iv, true).unwrap();
        assert_eq!(plaintext, decrypted_plaintext);
    }

    #[test] // Challenge 10
    fn test_challenge_10() {
        let ciphertext: Vec<u8> = from_base64(
            fs::read_to_string("tst/data/10.txt")
                .expect("Cannot read input data")
                .replace('\n', "")
                .as_str(),
        );
        let key = "YELLOW SUBMARINE";
        let iv = vec![0u8; key.len()];
        let plaintext =
            aes_128_cbc_decrypt(&ciphertext, &key.as_bytes().to_vec(), &iv, true).unwrap();
        let prelude = "I'm back and I'm ringin' the bell";
        assert_eq!(
            prelude,
            String::from_utf8(plaintext[0..prelude.len()].to_vec()).unwrap()
        );
    }
}
