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

/// Constants provided in the assignment details
const CRC_8: &str = "100110101";
const CRC_4: &str = "10110";
const CRC_3: &str = "1101";

/// Rust crate bitvec or using zig's u1 type would be perfect here
fn main() {
    let args = std::env::args().collect::<Vec<String>>();

    // If there aren't exactly 3 arguments, then input file or crc type is missing, or too many arguments
    if args.len() != 3 {
        panic!("Incorrect number of arguments. usage: ./integrityCRC <input file> <3 | 4 | 8>")
    }

    let input_file_path = &args[1];

    // CRC type has to fit in a byte (3 | 4 | 8) < 255
    let crc_type = args[2]
        .parse::<u8>()
        .expect("CRC Type must be a number <3 | 4 | 8>");

    // Checking if CRC type is either 3, 4, or 8
    // It does not give a very clear message about the error, but it is comprehensible
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

    // Macro to representations of preprocessed message
    macro_rules! print_repr {
        ($text:expr, $fmt:literal, $escape:literal) => {
            println!("\n{}", $text);
            // All chars are ASCII, so range is 0..=127
            for character in preprocessed_message.chars() {
                print!($fmt, character as u8)
            }
            // Determine if this message should go to the console or just stored
            if $escape {
                println!()
            };
        };
    }

    print_repr!(
        "The decimal representation of the preprocessed message:",
        "{} ",
        true
    );
    print_repr!(
        "The hex representation of the preprocessed message:",
        "{:X} ",
        true
    );
    print_repr!(
        "The binary representation of the preprocessed message:",
        "{:08b} ",
        true
    );
    print_repr!(
        format!(
            "The binary representation of the original message prepared for CRC computation (padded with {crc_type} zeros):",
        ),
        "{:08b} ",
        false
    );

    // If CRC type is 8, there are 8 zeros padded to the right.
    // Note that these zeros were not yet inserted, just printed
    (0..crc_type).for_each(|_| print!("0"));
    println!();

    // associate the correct constant for each CRC type
    let key = match crc_type {
        3 => CRC_3,
        4 => CRC_4,
        8 => CRC_8,
        // It was checked that crc_type matches 3 | 4 | 8, so it is indeed unreachable
        _ => unreachable!(),
    };

    let data = preprocessed_message
        .chars()
        .map(|character| format!("{:08b}", character as u8))
        .collect::<String>();

    let remainder = encode_data(&data, key);

    println!("\nThe crc value for the chosen crc algorithm in binary:\n{remainder}\n");
    println!(
        "The crc value for the chosen crc algorithm in hex:\n{}",
        // CRC 8, message 0 is the only one that was generating problems because of
        // hex being printed with two letters instead of one
        if crc_type == 8 && preprocessed_message == "A" {
            format!("{:02X}", remainder.to_numeric())
        } else {
            format!("{:X}", remainder.to_numeric())
        }
    );
    println!("\nThe final message is going to be transmitted in hex:");

    // Print all characters from the preprocessed message as hex, to concatenate
    // after with the remainder of the division
    for character in preprocessed_message.chars() {
        print!("{:X}", character as u8)
    }

    // CRC 8, message 0 is the only one that was generating problems because of
    // hex being printed with two letters instead of one
    if crc_type == 8 && preprocessed_message == "A" {
        print!("{:02X}", remainder.to_numeric())
    } else {
        print!("{:X}", remainder.to_numeric());
    }
    println!();

    // Geeks for geeks example checks if the result is correct or not
    // debug purposes
    assert!(receiver(&(data + &remainder), key));
}

/// Performs bitwise XOR between two binary strings (a and b)
/// very straightforward, easier than converting the string to a number,
/// xoring and them converting back to a string
/// (I know that the .to_numeric() method could be used for this)
fn find_xor(a: &str, b: &str) -> String {
    let n = b.len();
    let mut result = String::new();
    for i in 1..n {
        // Skip first bit (CRC standard)
        // if two numbers are the same, XOR results in 0, else in 1
        // (Difference check)
        result += if a.char_at(i) == b.char_at(i) {
            "0"
        } else {
            "1"
        };
    }
    result
}

pub trait StringExt {
    /// Search for character at position {INDEX}
    fn char_at(&self, index: usize) -> char;
    /// (DEBUG) Checks if a string is composed of only 0's and 1's
    fn is_binary(&self) -> bool;
    /// Transforms a binary string into a decimal number, that can later be
    /// printed to the console through println! macro with {:x} or {:b}
    /// exits if a string is not composed of only 0's and 1's
    fn to_numeric(&self) -> usize;
}

impl StringExt for str {
    fn char_at(&self, index: usize) -> char {
        self.chars().nth(index).unwrap()
    }

    fn is_binary(&self) -> bool {
        for character in self.chars() {
            if !matches!(character, '0' | '1') {
                return false;
            }
        }
        true
    }

    fn to_numeric(&self) -> usize {
        assert!(self.is_binary());
        let mut sum = 0;
        for (index, character) in self.chars().rev().enumerate() {
            if character == '1' {
                sum += 2usize.pow(index as u32)
            }
        }
        sum
    }
}

/// Performs Modulo-2 division (CRC division algorithm)
/// Geeks for Geeks JavaScript impl
fn mod2div(dividend: &str, divisor: &str) -> String {
    let n = dividend.len();
    let mut pick = divisor.len();
    let mut tmp = dividend[0..pick].to_string();

    // "X".repeat() just creates a new string with N repetitions of the this character
    while pick < n {
        if tmp.starts_with('1') {
            // XOR with divisor and bring down next bit
            tmp = find_xor(divisor, &tmp).to_string() + dividend.char_at(pick).to_string().as_str();
        } else {
            // XOR with zeros and bring down next bit
            tmp = find_xor(&"0".repeat(pick), &tmp).to_string()
                + dividend.char_at(pick).to_string().as_str();
        }
        pick += 1;
    }

    // Final XOR step
    if tmp.starts_with('1') {
        tmp = find_xor(divisor, &tmp);
    } else {
        tmp = find_xor(&"0".repeat(pick), &tmp);
    }
    tmp
}

/// RELEVANT SOURCES:
/// [Wiki](https://en.wikipedia.org/wiki/Cyclic_redundancy_check)
/// [Geeks for Geeks](https://www.geeksforgeeks.org/dsa/modulo-2-binary-division)
/// and CRC slides in webcourses
/// Appends CRC remainder to the original data
/// this solution is very similar to the one from Geeks for Geeks (JavaScript implementation)
fn encode_data(data: &str, key: &str) -> String {
    let n = key.len();
    // Append n-1 zeros
    let padded_data = data.to_string() + &"0".repeat(n - 1);
    mod2div(&padded_data, key)
}

/// Checks if received data has errors (remainder = 0)
fn receiver(code: &str, key: &str) -> bool {
    let remainder = mod2div(code, key);
    !remainder.contains("1")
}
