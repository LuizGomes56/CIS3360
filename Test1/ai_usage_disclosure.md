# AI Usage Disclosure Details

**Student Name:** Luiz Gustavo Santana Dias Gomes


**Student ID:** 5678035


**Assignment:** 1 - Hillrail

---

## Instructions

Complete this template with detailed information about your AI usage. Submit this file along with your signed PDF declaration form.

---

## AI Tool #1

### Tool Name
ChatGPT

### Version/Model
GPT 5 Thinking

### Date(s) Used
September 4 and 5

### Specific Parts of Assignment
function `join_columns` for `trait Matrix`, closure `print_80_per_line`, and a function block.
Everything is marked with `#![CHATGPT 5 THINKING]` and a very detailed comment below it.

### Prompts Used
1. I have a string slice with only ASCII characters, and I have a Matrix `type: Vec<Vec<usize>>` zeroed, how to insert each char in that matrix as COLUMN by COLUMN, instead of row by row?
    - Number of elements per row is given at variable number_of_elements_per_row,
    - Number of columns is given at variable matrix_columns
    - String slice is given at variable plaintext
    - Matrix is given at variable matrix_b
    - AI answered the code in that block, and I only added the comments of my interpretation of it

2. In Rust, create a function that takes in a string and prints with the following specifications: 
    - a maximum of 80 characters per line, if there's overflow, print in the next line
    - all characters are valid ASCII

3. I have a `&self` and a method `join_columns` that should:
    - Take on `&self` an `impl AsRef<[Vec<usize>]>` (Matrix is aligned) and join in a string column by column instead of row by row
    - all characters in it are valid ASCII, so convert them to char

### AI Output/Results
1. RESULT:
```rs
for col in 0..number_of_elements_per_row {
    for row in 0..matrix_columns {
        let index = matrix_columns * col + row;
        matrix_b[row][col] = plaintext.chars().nth(index).unwrap() as usize - b'A' as usize;
    }
}
```
- NOTE: I Added `- b'A' as usize` to fullfill the assignment's requirements

2. RESULT:
```rs
fn join_columns(&self) -> String {
    let mut result = String::new();
    for col in 0..self.num_columns() {
        for row in self.as_ref() {
            result.push(row[col] as u8 as char);
        }
    }
    result
}
```

3. RESULT:
```rs
fn print_80_per_line(s: &str) {
    for chunk in s.as_bytes().chunks(80) {
        println!("{}", std::str::from_utf8(chunk).unwrap());
    }
};
```
- This was transformed into a closure by me.

### How Output was Verified/Edited
I went on Rust playground website and provided sample inputs, and checked if the result was correct. I made comments of my interpretation of that code afterwards, and for one of them, I transformed the function provided into a closure

### Multiple Iterations (if applicable)
Not applicable

### Learning & Reflection
- I learned how to print 80 characters into the console, and adding a new lines those that did not fit. Initially I tried using `println!("... {:80}", ...)` to see if it would work, but it did not, so I asked the AI to do this basic task for me.
- I learned how to insert in an matrix-like array column by column, and how to join them in a single string. Before that I only tried row-by-row.

--- 
## Overall Reflection

I only used AI for very basic tasks, that were helpful because I was thinking of creating a function to transpose the matrix, but the AI provided a code that was more efficient and saved me time in this task that were not really the main focus of the assignment. The same can be said to the function to print values to the console (In C it would be much more straightforward, but this functionality is not included in Rust since most of the times the Debug trait already solves everyone's problems: `"{:#?}"`)

---
