/*
Assignment:
hillrail - Hill cipher followed by Rail Fence transposition

Author: Luiz Gustavo Santana Dias Gomes
NID: lu123351
UCFID: 5678035
Language: C, C++, or Rust (only)

To Compile :
gcc     -O2    -std=c11     -o hillrail hillrail.c
g++     -O2    -std=c++17   -o hillrail hillrail.cpp
rustc   -O      hillrail.rs     -o hillrail

To Execute (on Eustis):
./hillrail encrypt key.txt plain.txt <depth>

where:
    key.txt     = key matrix file
    plain.txt   = plaintext file
    <depth>     = integer >= 2 (Rail Fence)

Notes:
    - Input is 8 - bit ASCII; process only A-Z (uppercase).
    - Tested on Eustis.

Class: CIS3360 - Security in Computing - Fall 2025
Instructor: Dr. Jie Lin
Due Date: September 12th 2025
*/

// Suppress warnings
#![allow(dead_code)]

use std::str::Split;

fn main() {
    /* Example of what comes in std::env::args on my machine
    Arguments: Args {
        inner: [
            "C:\\..\\hillrail.exe",
            "encrypt",
            "key.txt",
            "plain.txt",
            "d",
        ],
    }*/
    // Get a Vec of Strings that represent each argument provided
    let process_args = std::env::args().collect::<Vec<String>>();
    // .expect will exit the program if the format is passed is not correct
    let key_path = process_args.get(2).expect("No key file path provided");
    let plaintext_path = process_args
        .get(3)
        .expect("No plaintext file path provided");
    // .parse to convert the String to an integer, if it fails, there's an invalid input
    let rail_fence_depth = process_args
        .get(4)
        .expect("No rail fence depth provided")
        .parse::<usize>()
        .expect("Depth should be an integer");

    // Read contents to a full String, instead of line by line
    let key_file_content = std::fs::read_to_string(key_path)
        .expect("Failed to read key file")
        // Some \r were present in the document
        .replace("\r", "");
    let plaintext_file_content =
        std::fs::read_to_string(plaintext_path).expect("Failed to read plaintext file");

    // The matrix dimension is a single integer in the first line
    // String.split("\n")[0] will yield the first line
    let matrix_dimension = key_file_content
        .split("\n")
        .collect::<Vec<_>>()
        .iter()
        // Some strings were empty
        .filter_map(|v| (!v.is_empty()).then_some(v))
        // get back the values and return the first value
        .collect::<Vec<_>>()[0]
        .parse::<usize>()
        .expect("The matrix dimension was not a valid number");

    let row_major_entries = key_file_content
        // Split by lines
        .lines()
        // skip the first one (because it is the number of rows)
        .skip(1)
        .collect::<Vec<_>>()
        // this is a vec of lines
        .into_iter()
        .map(|line| {
            let get_number_vec = |v: Split<'_, &'static str>| {
                v.into_iter()
                    // get only the values that are numbers (so they must be able to be)
                    // parsed into <usize> type
                    .filter_map(|v| {
                        if !v.is_empty() {
                            match v.parse::<usize>() {
                                Ok(usize_value) => Some(usize_value),
                                Err(_) => None,
                            }
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<usize>>()
            };

            // each line is in the format {number}\t{number}\t...
            let split_tabs = get_number_vec(line.split("\t"));
            if split_tabs.is_empty() {
                // Split in tabs did not work (The examples are inconsistent!)
                // Some examples are escaped with tabs, others with whitespaces
                // try here with whitespaces
                let split_whitespaces = get_number_vec(line.split(" "));
                if split_whitespaces.is_empty() {
                    panic!("Matrix numbers weren't scaped with either tabs or whitespaces");
                }
                split_whitespaces
            } else {
                split_tabs
            }
        })
        .collect::<Vec<_>>();

    println!("Key matrix:");
    row_major_entries.display_raw();

    // store the result of the plaintext file parsing
    let mut plaintext_result = String::new();

    // go through each character in that file and check if they're alphabetic letters
    // if not, do not push to the result
    for character in plaintext_file_content.chars() {
        match character {
            // if it is already in uppercase
            'A'..='Z' => plaintext_result.push(character),
            // if not in uppercase, convert it
            'a'..='z' => plaintext_result.push_str(&character.to_uppercase().to_string()),
            // was not an alphabetic character
            _ => continue,
        };
    }
    // check plaintext_result and see if it is a multiple of "n"
    // "n" was the matrix dimension
    // if not, add "X" until it becomes a multiple
    // the best way to do that is see if the division is exact

    println!("\nPlaintext:\n{}", plaintext_result);

    let mut result = plaintext_result.len() / matrix_dimension;
    while result * matrix_dimension != plaintext_result.len() {
        plaintext_result.push('X');
        // avoid an infinite loop
        result = plaintext_result.len() / matrix_dimension;
    }

    let ciphertext = generate_ciphertext(&row_major_entries, &plaintext_result);
    println!("\nCiphertext:\n{}", ciphertext);
    println!("\nDepth: {}", rail_fence_depth);
}

// Parameter "matrix" implements Matrix<usize> trait
// L4 Symmetric Crypto.pdf page 30 (WEBCOURSES)
fn generate_ciphertext(matrix: &[Vec<usize>], plaintext: &str) -> String {
    assert!(matrix.is_square_matrix(), "Matrix is not square");
    // generate matrix to plaintext with depth N
    // number of columns that arg 1 has
    let matrix_columns = matrix.num_columns();

    // plaintext here was already filled with "X"'s if not exact
    let number_of_elements_per_row = plaintext.len() / matrix_columns;

    // new matrix to be created
    let mut matrix_b = vec![vec![0; number_of_elements_per_row]; matrix_columns];

    // fill indexes
    // Example: (A B C D E F G H) -> (A, B); (C, D); (E, F); (G, H)
    for col in 0..number_of_elements_per_row {
        for row in 0..matrix_columns {
            let index = matrix_columns * col + row;
            matrix_b[row][col] = plaintext.chars().nth(index).unwrap() as usize;
        }
    }

    println!("------------------------");
    println!("Matrix_A:");
    matrix.display_raw();
    println!("------------------------");
    println!("Matrix_B:");
    matrix_b.display_raw();
    println!("------------------------");

    // if matrix has 2 columns, b must have 2 rows; 7 columns -> 7 rows and so on
    let mut result = matrix_multiply(matrix, &matrix_b);

    println!("Result:");
    result.display_raw();
    println!("------------------------");
    apply_mod_26(&mut result);

    result.join_columns()
}

#[doc = "Subtract 'A' in binary form and apply mod 26 on it, then add 'A' again"]
fn apply_mod_26(matrix: &mut [Vec<usize>]) {
    for row in matrix {
        for column in row.iter_mut() {
            // ! This is super important; 'A' as usize does not result in zero
            // ! since we only deal with uppercase alphabetic letters, - 'A' as usize
            // ! will align the indexes; maybe this shouldn't be done here
            // ! but I decided to do it anyway; after doing the mod 26, add that value back
            // ! this is because to display in console, it is easier to cast as u8 then char
            // ! than creating a 26 char array and map each one to it
            // * also easier to debug!
            assert!(matches!(*column as u8, b'A'..=b'Z'));
            *column -= b'A' as usize;
            *column %= 26;
            *column += b'A' as usize;
        }
    }
}

/// Usage of columns and rows repeat quite a bit
/// Adding methods will make it easier to read what is going on
/// better than implementing multiple functions
trait Matrix {
    #[doc = "Prints the matrix in a raw format (As numbers)"]
    fn display_raw(&self);
    #[doc = "Takes every element of the vec, in order and joins in a single string"]
    #[doc = "Order: First row -> Print all columns, then move to the next one"]
    /// I created this function first but I realised it was not matching the expected
    /// results, and the matrix it was receiving was correct. I'm leaving its definition
    /// despite not being used
    fn join_rows(&self) -> String;
    #[doc = "Goes column by column concatenating the result into a string"]
    fn join_columns(&self) -> String;
    #[doc = "Returns the number of columns (Crashes the program if not aligned)"]
    fn num_columns(&self) -> usize;
    #[doc = "Returns the number of rows"]
    fn num_rows(&self) -> usize;
    #[doc = "Returns a column N value (Like a[0][0], a[1][0], a[2][0], ...)"]
    fn get_column(&self, n: usize) -> Vec<usize>;
    #[doc = "Returns a row N value. Crashes if out of bounds"]
    fn get_row(&self, n: usize) -> &[usize];
    #[doc = "Checks if the matrix is square (like 2x2, 3x3, ...)"]
    fn is_square_matrix(&self) -> bool;
}

/// T: AsRef<[Vec<usize>]> to allow Slices to use this trait (not only Vecs!)
/// Avoids some `.clone` calls
impl<T: AsRef<[Vec<usize>]>> Matrix for T {
    fn join_rows(&self) -> String {
        let mut result = String::new();
        for row in self.as_ref() {
            for col in row.iter() {
                // *col is a letter from alphabet character, so its ascii
                // as u8 won't truncate in this case
                result.push(*col as u8 as char);
            }
        }
        result
    }
    fn join_columns(&self) -> String {
        let mut result = String::new();
        // start with columns then move to rows
        // recall that num_columns exits if matrix is not aligned
        for col in 0..self.num_columns() {
            for row in self.as_ref() {
                // row[col] won't give errors since matrix is aligned
                result.push(row[col] as u8 as char);
            }
        }
        result
    }
    fn display_raw(&self) {
        for row in self.as_ref() {
            for (i, col) in row.iter().enumerate() {
                // print everything with an tab in between
                print!("{col}");
                if i != row.len() - 1 {
                    // that is the format that is in the provided test cases
                    print!("\t");
                }
            }
            println!();
        }
    }

    fn num_rows(&self) -> usize {
        self.as_ref().len()
    }

    fn num_columns(&self) -> usize {
        let mut num_cols = 0;
        // number of rows is just the number of arrays inside of the main one
        for row in self.as_ref() {
            if num_cols == 0 {
                // assign number of columns to be the length of the array
                // that represent the first row
                num_cols = row.len();
            } else if num_cols != row.len() {
                // if the number of elements in the second row or further
                // is not the same as the first one, then it is not a square matrix
                panic!("Number of columns is not the same for every row. Matrix not aligned");
            }
        }
        num_cols
    }

    fn is_square_matrix(&self) -> bool {
        // if passed through the for loop, then it must be an at least aligned matrix
        // here it will check if it is in fact an square one
        return self.num_columns() == self.num_rows();
    }

    fn get_row(&self, n: usize) -> &[usize] {
        self.as_ref()
            .get(n)
            .expect(&format!("There's no row in index {n}"))
    }

    fn get_column(&self, n: usize) -> Vec<usize> {
        let mut result = Vec::new();
        for row in self.as_ref() {
            let try_get_column = row.get(n).expect("Matrix was not aligned or square");
            result.push(try_get_column.clone())
        }
        result
    }
}

/*
Pseudocode provided:
Algorithm 1 MATRIX-MULTIPLY(A, B)
1: if A.columns != B.rows then
2:  error "incompatible dimensions"
3: else
4:  let C be a new A.rows x B.columns matrix
5:  for i = 1 -> A.rows do
6:      for j = 1 -> B.columns do
7:          c_ij = 0
8:          for k = 1 -> A.columns do
9:              c_ij = c_ij + a_ik * b_kj
10: return C
*/

/// both A and B are 2D matrices (Translation of the code above)
#[doc = "Multiply two matrices. This is the translation from pseudocode provided"]
fn matrix_multiply(a: &[Vec<usize>], b: &[Vec<usize>]) -> Vec<Vec<usize>> {
    let a_num_rows = a.num_rows();
    let a_num_cols = a.num_columns();
    let b_num_cols = b.num_columns();
    let b_num_rows = b.num_rows();

    if a_num_cols != b_num_rows {
        panic!("incompatible dimensions");
    } else {
        // initialize the whole matrix with zeros (skip step c[i][j] = 0)
        let mut c: Vec<Vec<usize>> = vec![vec![0; b_num_cols]; a_num_rows];
        for i in 0..a_num_rows {
            for j in 0..b_num_cols {
                for k in 0..a_num_cols {
                    c[i][j] = c[i][j] + a[i][k] * b[k][j];
                }
            }
        }
        return c;
    }
}
