# AES Algorithm




## About The Project

An implementation of the AES algorithm encryption and decryption in Python 3

Encryption modes: 128 bit, 192 bit & 256 bit

## Why use AES?
The Advanced Encryption Standard (AES) is a symmetric block cipher chosen by the U.S. government to protect classified information.

**Security**: Competing algorithms were to be judged on their ability to resist attack as compared to other submitted ciphers. Security strength was to be considered the most important factor in the competition.

**Cost**: Intended to be released on a global, nonexclusive and royalty-free basis, the candidate algorithms were to be evaluated on computational and memory efficiency.

**Implementation**. Factors to be considered included the algorithm's flexibility, suitability for hardware or software implementation, and overall simplicity.

## File Contents

**AES.py**: encryption

**InverseAES.py**: decryption

**unitTest.py**: used to test function independently. [Found here](https://userlab.utk.edu/courses/cosc483/resources/aes-unit-tests)

**unitTestArray**: a list of array provided as an input when running test. [Found here](https://userlab.utk.edu/courses/cosc483/resources/aes-arrays)

**Array.py**: included substitution box (S-box), inverse substitution box (InvBox). [Found here](https://userlab.utk.edu/courses/cosc483/resources/aes-arrays)

## How to compile and run code

**AES.py** and **InverseAES** can run independently but they **ARE NOT** produce any output file. Instead, each function return some values depended on the purpose of it.

The program will perform testes based on a pre-define (correct) value from each function and produce an output file called **output.txt**

To compile and run the program. 

     python3 unitTest.py

     
## Project Content
This project built based on the AES implementation as described in [FIPS 197](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf) specification.

You can find the following function described in the document here:

**Encryption**:
      
     SubBytes(): applies the S-box to each byte of the State
     S-box: substitution values for the byte xy (in hexadecimal format)
     ShiftRows(): cyclically shifts the last three rows in the State
     MixColumns(): operates on the State column-by-column
     AddRoundKey(): XORs each column of the State with a word from the key
     
**Decryption**:

    Inverse of the encryption functions above

























    
