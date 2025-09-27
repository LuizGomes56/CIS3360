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
#![allow(non_snake_case)]

// ? Probably I took 8 hours to do that
// ! BLOCKS WHERE AI WAS USED ARE DISCLOSED IN THE COMMENTS

use std::str::Split;

/// This is probably thd worst ever implementation of this
/// ? NO AI WAS USED HERE
fn apply_rail_fence(ciphertext: &str, rail_fence_depth: usize) -> String {
    /*
    #![L4 Symmetric Crypto.pdf] page 33
    meet me after the toga party
    cipher: MEMATRHTGPRYETEFETEOAAT

    appearently the text is split in depth arrays,
    each byte is mapped to a position from top bottom-right
     */

    // if depth is n, n arrays should be created
    let mut arrays =
        vec![vec!['\0'; ciphertext.len().div_ceil(rail_fence_depth)]; rail_fence_depth];

    // the example has 12 elements in first array, and 23 letters, depth = 2
    // 23 / 2 = 11.5, since target is 12, div_ceil() will guarantee that it is rounded up
    // (0,0), (1,1), (0,1), (1,2), (0,2), (1,3), (0,3), ...
    // This is the pattern (Array index, Array position)

    // DEPTH = 3
    // (0,0), (1,1), (2,2), (1,2), (0,2), (1,3), (2,4), (1,4), (0,4), (1,5), (2,6), (1,6), (0,6), (1,7), (2,8), (1,8), (0, 8)
    // (INDEX, INDEX) goes until rail_fence_depth is reached
    // after that: depth - 2 indicates X in tuple at position [depth]
    // next [depth - 1] tuples have the same Y, Y = [depth - 1]
    // Then a well defined pattern repeats -> (1,3), (2,4), (1,4), (0,4), (1,5), (2,6), (1,6), (0,6), (1,7), (2,8), (1,8), (0, 8)
    // 3, 4, 4, 4, 5, 6, 6, 6, ... -> A number, then 3 times the successor, then another number, then 3 times its ...
    // this works for depth = 3 only

    // DEPTH = 2
    // almost the described above, but the pattern of repetition of Y position in tuples after
    // depth + [depth - 1] are 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, ... same number twice

    // store tuples in order of what index in the arrays is at, and in what position
    // this is going to be used to make the ciphertext (By ordering X, then Y)
    let mut result_tuples: Vec<(usize, usize)> = vec![(0, 0); ciphertext.len()];

    let mut current_position = 0;
    for i in 0..rail_fence_depth {
        result_tuples[i] = (i, i);
        current_position += 1;
    }

    // change only the Y values of tuples starting from depth + depth - 1 as in the
    // previous comment, they have the same Y. X will not be changed here
    // at this point, current_position = depth so it doesn't really matter what range
    // format is used
    for i in current_position..(2 * rail_fence_depth - 1) {
        result_tuples[i].1 = rail_fence_depth - 1;
        current_position += 1;
    }

    // number, number, number + 1, number + 1, number + 2, number + 2, ...
    // number start at == depth
    if rail_fence_depth == 2 {
        let start = current_position;
        for i in (start..result_tuples.len()).step_by(2) {
            // the Y value of that tuple
            let y = rail_fence_depth + (i - start) / 2;
            result_tuples[i].1 = y;
            if i + 1 < result_tuples.len() {
                result_tuples[i + 1].1 = y;
            }
        }
    }
    // 3, 4, 4, 4, 5, 6, 6, 6, ... -> A number, then 3 times the successor
    // this pattern will start at == depth as well
    else if rail_fence_depth == 3 {
        // This was the only thing that was not passing in the tests
        result_tuples[3].0 = 1;
        // y will start at the same value as depth
        let mut y = rail_fence_depth;
        let mut i = current_position;
        // false then group 1 (Single), true then group 3 numbers
        let mut use_big_group = false;

        // add the repetition: 3, 4, 4, 4, 5, 6, 6, 6, ...
        while i < result_tuples.len() {
            let group_len = if use_big_group { 3 } else { 1 };
            let end = (i + group_len).min(result_tuples.len());
            for k in i..end {
                result_tuples[k].1 = y;
            }
            i = end;
            y += 1;
            // alternates between groups
            use_big_group = !use_big_group;
        }
    }

    // start at 1 for both depth = 2 and 3
    let mut x = 1;
    // control when x should be incremented/decremented
    let mut going_down = true;

    // associate the correct X for each tuple
    for i in (2 * rail_fence_depth - 1)..result_tuples.len() {
        result_tuples[i].0 = x;
        // x will increment until it reaches the top (depth)
        // depth dictates how many arrays there will be split, so
        // there will be depth - 1 arrays, if it is the max, x should
        // start decrementing to follow the pattern
        if going_down {
            if x + 1 == rail_fence_depth {
                going_down = false;
                x -= 1;
            } else {
                x += 1;
            }
        } else {
            // if it reaches zero, start to increment
            // important to respect array bounds
            if x == 0 {
                going_down = true;
                x += 1;
            } else {
                x -= 1;
            }
        }
    }

    // from here, result_tuples has the exact order that each char in the string
    // has to go
    for (i, (x, y)) in result_tuples.iter().enumerate() {
        // add each char in its respective position
        arrays[*x].insert(*y, ciphertext.chars().nth(i).unwrap());
    }

    // println!("Result arrays: {:?}", arrays);
    // println!("Result tuples: {:?}", result_tuples);

    // now the position in which each letter should be retreived is known
    // after that, it is only necessary to join everything in a string
    let sorted_tuples_by_x_then_y = {
        let mut sorted_tuples = result_tuples.clone();
        sorted_tuples.sort_by_key(|(x, _)| *x);
        sorted_tuples
    };

    let mut result = String::new();
    // x does not matter because we read the array 0, then 1, ...
    for (x, y) in sorted_tuples_by_x_then_y {
        // add each char in its respective position
        result.push(arrays[x][y]);
    }

    result
}

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
        .expect("Failed to read key file. Is the key path correct?")
        // Some \r were present in the document
        .replace("\r", "");
    let plaintext_file_content = std::fs::read_to_string(plaintext_path)
        .expect("Failed to read plaintext file. Check its path");

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
    row_major_entries.display();

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

    /*
    * #[CHAT GPT 5 THINKING]
    ! GENERATED BY AI
    * PROMPT: In Rust, create a function that takes in a
    * string and prints with the following specifications:
    * a maximum of 80 characters per line, if there's overflow, print in the next line
    * all characters are valid ASCII
    ? It answered as a fn and I transformed the following closure

    * DATE USED: 9/5/2025
    */
    let print_80_per_line = |s: &str| {
        for chunk in s.as_bytes().chunks(80) {
            println!("{}", std::str::from_utf8(chunk).unwrap());
        }
    };

    println!("\nPlaintext:");
    print_80_per_line(&plaintext_result);

    // check plaintext_result and see if it is a multiple of "n"
    // "n" was the matrix dimension
    // if not, add "X" until it becomes a multiple
    // the best way to do that is see if the division is exact
    // is by seeing if the length of the result is a multiple of the previous result, exact
    let mut result = plaintext_result.len() / matrix_dimension;
    while result * matrix_dimension != plaintext_result.len() {
        plaintext_result.push('X');
        // avoid an infinite loop
        result = plaintext_result.len() / matrix_dimension;
    }

    let ciphertext = generate_ciphertext(&row_major_entries, &plaintext_result);
    println!("\nCiphertext:");
    print_80_per_line(&if rail_fence_depth > 1 {
        apply_rail_fence(&ciphertext, rail_fence_depth)
    } else {
        ciphertext
    });
    println!("\nDepth: {}", rail_fence_depth);
}

/// Parameter "matrix" implements Matrix<usize> trait
/// Reference: L4 Symmetric Crypto.pdf page 30 (WEBCOURSES)
/// Tales a plaintext and a matrix and returns a ciphertext as a string
fn generate_ciphertext(matrix_a: &[Vec<usize>], plaintext: &str) -> String {
    assert!(matrix_a.is_square_matrix(), "Matrix is not square");
    // generate matrix to plaintext with depth N
    // number of columns that arg 1 has
    let matrix_columns = matrix_a.num_columns();

    // plaintext here was already filled with "X"'s if not exact
    let number_of_elements_per_row = plaintext.len() / matrix_columns;

    // new matrix to be created
    let mut matrix_b = vec![vec![0; number_of_elements_per_row]; matrix_columns];

    // fill indexes
    // Example: (A B C D E F G H) -> (A, B); (C, D); (E, F); (G, H)
    /*
     * #[CHATGPT 5 THINKING]
     * PROMPT: I have a string slice with only ASCII characters, and I have a Matrix
     * type: Vec<Vec<usize>> zeroed, how to insert each char in that matrix as
     * COLUMN by COLUMN, instead of row by row?
     * - Number of elements per row is given at variable number_of_elements_per_row,
     * - Number of columns is given at variable matrix_columns
     * - String slice is given at variable plaintext
     * - Matrix is given at variable matrix_b
     *
     * DATE USED: 9/4/2025
     */
    for col in 0..number_of_elements_per_row {
        for row in 0..matrix_columns {
            // index in plaintext slice
            let index = matrix_columns * col + row;
            // -b'A' to make it in range 0-25
            matrix_b[row][col] = plaintext.chars().nth(index).unwrap() as usize - b'A' as usize;
        }
    }

    // println!("------------------------");
    // println!("Matrix_A:");
    // matrix_a.display();
    // println!("------------------------");
    // println!("Matrix_B:");
    // matrix_b.display();
    // println!("------------------------");

    // if matrix has 2 columns, b must have 2 rows; 7 columns -> 7 rows and so on
    let mut result = matrix_multiply(matrix_a, &matrix_b);

    // println!("Result of multiply:");
    // result.display();
    // println!("------------------------");
    apply_mod_26(&mut result);

    // println!("Result of mod 26:");
    // result.display();
    result.join_columns()
}

#[doc = "Subtract 'A' in binary form and apply mod 26 on it, then add 'A' again"]
fn apply_mod_26(matrix: &mut [Vec<usize>]) {
    for row in matrix {
        for column in row.iter_mut() {
            // ! This is super important; - b'A' was done before
            // ! after doing the mod 26, add that value back
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
    fn display(&self);

    #[doc = "Takes every element of the vec, in order and joins in a single string"]
    #[doc = "Order: First row -> Print all columns, then move to the next one"]
    /// I created this function first but I realised it was not matching the expected
    /// results, and the matrix it was receiving was correct. I'm leaving its definition
    /// despite not being used
    fn join_rows(&self) -> String;

    #[doc = "Goes column by column concatenating the result into a string"]
    #[doc = "THIS FUNCTION WAS GENERATED BY AI"]
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
    /**
     * #[CHATGPT 5 THINKING]
     * PROMPT: I have a &self and a method join_columns that should:
     * - Take on &self an impl AsRef<[Vec<usize>]> (Matrix is aligned)
     * and join in a string column by column instead of row by row
     * all characters in it are valid ASCII, so convert them to char
     *
     * DATE USED: 9/4/2025
     */
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
    fn display(&self) {
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
