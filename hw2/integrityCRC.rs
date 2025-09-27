/*
Assignment:
integrityCRC - CRC Algorithm Implementation

Author: Luiz Gustavo Santana Dias Gomes

Language: C, C++, or Rust (only)

To Compile:
    gcc -O2 -std=c11 -o integrityCRC integrityCRC.c
    g++ -O2 -std=c++17 -o integrityCRC integrityCRC.cpp
    rustc -O integrityCRC.rs -o integrityCRC

To Execute (on Eustis):
    ./integrityCRC <message_file> <crc_algorithm>

where:
    <message_file> is the path to the input text file
    <crc_algorithm> is 3, 4, or 8 (for CRC-3, CRC-4, or CRC-8)

Notes:
    - Implements CRC-3, CRC-4, and CRC-8 algorithms
    - Processes plain text messages and computes CRC values
    - Outputs all intermediate steps and final CRC values
    - Tested on Eustis.

Class: CIS3360 - Security in Computing - Fall 2025

Instructor: Dr. Jie Lin

Due Date: Friday, October 17, 2025 at 11:55 PM ET
*/

const CRC_8: usize = 0b100110101;
const CRC_4: usize = 0b10110;
const CRC_3: usize = 0b1101;

/// Rust crate bitvec would be perfect here
/// or using zig's u1 type (aka bit)
fn main() {
    let args = std::env::args().collect::<Vec<String>>();

    // If there aren't exactly 3 arguments, then input file or crc type is missing, or too many arguments
    if args.len() != 3 {
        panic!("usage: ./integrityCRC <input file> <3 | 4 | 8>")
    }

    let input_file_path = &args[1];

    // CRC type has to fit in a byte (3 | 4 | 8) < 255
    let crc_type = args[2].parse::<u8>().expect("CRC Type must be 3, 4, or 8");

    // Checking if CRC type is either 3, 4, or 8
    assert!(matches!(crc_type, 3 | 4 | 8));

    // Reading input file and exiting if it couldn't be readed
    let original_message = std::fs::read_to_string(input_file_path)
        .expect("Unable to read input file. Maybe path is wrong?");

    println!("The original message:\n{original_message}\n");

    // Remove any character that is not in the second argument of matches! macro
    let preprocessed_message = original_message
        .chars()
        .filter(|character| matches!(character, '0'..='9' | 'a'..='z' | 'A'..='Z'))
        .collect::<String>();

    println!("The preprocessed message (invisible characters removed):\n{preprocessed_message}");

    // Macro to print decimal, hex, binary representations of preprocessed message
    macro_rules! print_repr {
        ($repr:literal, $fmt:literal) => {
            println!(
                "\nThe {} representation of the preprocessed message:",
                $repr
            );
            for character in preprocessed_message.chars() {
                print!($fmt, character as u8)
            }
            println!();
        };
    }

    print_repr!("decimal", "{} ");
    print_repr!("hex", "{:x} ");
    print_repr!("binary", "{:08b} ");

    println!(
        "\nThe binary representation of the original message prepared for CRC computation (padded with {} zeros):",
        crc_type
    );
    for character in preprocessed_message.chars() {
        print!("{:08b} ", character as u8)
    }

    // If CRC type is 8, there are 8 zeros padded to the right.
    // Note that these zeros were not yet inserted, just printed
    (0..crc_type).for_each(|_| print!("0"));
    println!();

    // Store a vec of boolean (sizeof(bool) = 8, but suppose it is 1)
    let mut bitvec = Vec::<bool>::new();

    // Google: How to transform ASCII bytes into a bitvec in Rust
    for byte in preprocessed_message.as_bytes() {
        for j in 0..u8::BITS {
            let bit = (byte >> (7 - j)) & 1 != 0;
            bitvec.push(bit);
        }
    }

    // bitvec should have 8 * message_length elements
    let message_bitlength = preprocessed_message.len() << 3;

    // Debug assert
    assert_eq!(bitvec.len(), message_bitlength);

    // Add the padding bits
    (0..crc_type).for_each(|_| {
        bitvec.push(false);
    });
}

/// Google: How to get the nth bit of a byte in rust?
/// getting the nth bit of character, and casting converting to bool
fn nth_bit(number: usize, position: u32) -> bool {
    assert!(position < usize::BITS);
    ((number >> (usize::BITS - 1 - position)) & 1) != 0
}

/// CRC-8 yield results with 9 bits, I'm using usize
fn from_bitvec(bitvec: &[bool]) -> usize {
    // [1, 1, 0, 1] ->
    // 1 * 2 ** 0 -> 1
    // 0 * 2 ** 1 -> 2
    // 1 * 2 ** 2 -> 4
    // 1 * 2 ** 3 -> 8
    // result = 1 + 2 + 4 + 8 = 15
    let mut sum = 0;
    // reverse to start from LSB, i = 0;
    for (i, &byte) in bitvec.iter().rev().enumerate() {
        // value * 2 ** x
        sum += byte as usize * (1 << i);
    }
    sum
}

/// num can have > 8 bits because of CRC-8
fn to_bitvec(num: usize) -> Vec<bool> {
    (0..usize::BITS)
        .map(|i| nth_bit(num, i))
        .collect::<Vec<bool>>()
}

fn crc_algorithm() {}
