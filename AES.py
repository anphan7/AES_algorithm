'''
    Name: AN Phan
    Fix the k_sch print
'''
from Array import Array
import os.path

from unitTestArray import unitTestArray 
class AES:
    def __init__ (self):
        self.arr = Array()
        
    def ffAdd(self, a, b):
        '''
            Return the sum of two finite fields
        '''
        return a ^ b
    
    def xtime(self, a):
        '''
            Function make sure the input will not greater than x^8
            Return: output less than x^8 and shifted left 1
        '''
        return (a << 1) ^ 0x11b if a & 0x80 else a << 1

    def ffMultiply(self, a, b):
        '''
            Function take two bytes as input 
            Return a product of two byte as output
        '''
        sum = 0
        while a:
            if a & 0x01:
                sum ^= b
            b = self.xtime(b)
            a >>= 1
        return sum

    def subWord(self, a):
        '''
            Substitutes each byte in the state with corresponding row and column in SBox
            Return: a new word 
        '''
        # Split input into 4 
        # Ex: 0x00102030 -> 00 | 10 | 20 | 30

        # b1 = 0x30, b2 = 0x20, b3 = 0x10, b4 = 0x00
        #                           0x3        0x0
        b1 = self.arr.Sbox[(a & 0xF0) >> 4][(a & 0xF)] # => b1 = SBox[3][0]
        b2 = self.arr.Sbox[(a & 0xF000) >> 12][(a & 0xF00) >> 8] # => b2 = SBox[2][0]
        b3 = self.arr.Sbox[(a & 0xF00000) >> 20][(a & 0xF0000) >> 16] # => b3 = SBox[1][0]
        b4 = self.arr.Sbox[(a & 0xF0000000) >> 28][(a & 0xF000000) >> 24] # => b4 = SBox[0][0]
        
        new_a = 0
        # Concenate new byte
        return new_a ^ (b4 << 24) ^ (b3 << 16) ^ (b2 << 8) ^ b1
    
    def rotWord(self, word):
        '''
            Perform a cyclic permuation on its input word
            Return: a rotated new word
        '''
        # Ex: input word = 0x09cf4f3c
        new_word = (word << 8) & 0xFFFFFFFF # new_word = 0xcf4f3c00

        # rotate the word
        new_word |= ((word >> 24) & 0xFF) # => word = 0xcf4f3c09
        
        return new_word         
    '''
        Key -> 128 bit => nk = 4, nr = 10
            -> 192 bit => nk = 6, nr = 12
            -> 256 bit => nk = 8, nr = 14
    '''
    def keyExpansion(self, key, nk, nr):
        # key = 0x2b7e151628aed2a6abf7158809cf4f3c (128 bit)

        w = []
        nb = 4
        i = 0
        while i < nk:
            w.append( (key >> (32 * (nk - i - 1))) & 0xFFFFFFFF)
            i += 1
        # after the for loop => w = [2b7e1516, 8aed2a6a, bf715880, 09cf4f3c ]


        for i in range(nk, nb * (nr + 1)):
            temp = w[i-1]

            if i % nk == 0: 
                temp = self.subWord(self.rotWord(temp)) ^ self.arr.Rcon[i // nk]
            elif nk > 6 and i % nk == 4:
                temp = self.subWord(temp)
            w.append(w[i-nk] ^ temp)
        return w
    '''
        This transformation substitutes each byte in the State with its corresponding value from the S-Box.
        Return: new 2D array with substituted values from Sbox
    '''
    def subBytes(self, state):
        result = [[] for _ in range (4)]

        for r in range(4):
            for c in range(4):
                # at state[0][2] = 0x9a 
                # row: 0x9a & 0xF0 >> 4 = 0x9 --- col: 0x9a & 0xF0 = 0xa
                # replace the location row = 9 and col = 0 at the Sbox[9][0]
                row = (state[r][c] & 0xF0) >> 4
                col = state[r][c] & 0xF
                result[r].append(self.arr.Sbox[row][col])
        return result
    '''
        This transformation performs a circular shift on each row in the State (see Section 5.1.2)
    '''
    def shiftRows(self,state): # check unitTestArray for state example
        result = [[] for _ in range(4)]
        for row in range(4):
            ''' state[row][row:] state[row][:row] 
                -> [25, 160, 154, 233]  + []
                   [244, 198, 248]      + [61]
                   [141, 72]            + [227, 226]
                   [8]                  + [190, 43, 42]
            '''
            result[row] = state[row][row:] + state[row][:row]
        return result

    def mixColumn(self, s):
        result = [[0,0,0,0] for _ in range(4)]

        for c in range(4):
            
            result[0][c] = self.ffAdd(self.ffAdd(self.ffAdd(self.ffMultiply(0x02, s[0][c]), self.ffMultiply(0x03, s[1][c])), s[2][c]), s[3][c])
            result[1][c] = self.ffAdd(self.ffAdd(self.ffAdd(s[0][c], self.ffMultiply(0x02, s[1][c])), self.ffMultiply(0x03, s[2][c])), s[3][c])
            result[2][c] = self.ffAdd(self.ffAdd(self.ffAdd(s[0][c], s[1][c]), self.ffMultiply(0x02, s[2][c])), self.ffMultiply(0x03, s[3][c]))
            result[3][c] = self.ffAdd(self.ffAdd(self.ffAdd(self.ffMultiply(0x03, s[0][c]), s[1][c]), s[2][c]), self.ffMultiply(0x02, s[3][c]))
        #print(result)
        return result
    
    def addRoundKey(self, state, word, round):
        '''
            addRoundKey: generate keys from word then ->  keys ^ state
                state: input state 2D array
                word: words[] that generated from keyExpansion()
                round: value in range 0 <= round <= Nr
        '''
        # convert keys to matrix
        keys = self.keys(word, round)
        
        result = [[0,0,0,0] for _ in range(4)]
        nb = 4
        for r in range(4):
            for c in range(4):
                # xor the state and the keys
                result[r][c] = self.ffAdd(state[r][c], keys[r][c])
        
        return result

    def convert_toMatrix(self, input):
        '''
            Convert an input to matrix -> see Section 3.4
        '''
        m = [[] for _ in range(4)]
        for i in range(16):
            m[i % 4].append((input >> ((16 - i - 1) * 8)) & 0xFF)

        return m
    def print_matrix(self, matrix):
        m = [[0,0,0,0] for _ in range(4)]
        for r in range(4):
            for c in range(4):
                m[r][c] = hex(matrix[r][c])
        
        print(m)
     
    def trim_0x(self, input):
        '''
            Function trim the 0x from the input and add leading zero to make len = 32
        '''
        input = str(hex(input))
        output = input.replace("0x","")
        if len(output) < 32:
            
            addZero = 32 - len(output)
            a = [str(0) for _ in range (addZero)]
            b = "".join(a)
            return b + output
        elif len(output) == 45:
            addZero = 48 - len(output)
            a = [str(0) for _ in range (addZero)]
            b = "".join(a)
            return b + output 
        elif len(output) == 61:
            addZero = 64 - len(output)
            a = [str(0) for _ in range (addZero)]
            b = "".join(a)
            return b + output 
        return output

    def keys(self, word, round):
        keys = [[0,0,0,0] for _ in range (4)]
        nb = 4
        for r in range(4):
            for c in range(4):
                # word[round * nb + c] = pick a word at location (round * nb) at the same column
                # shift right  0, 8, 16, 32
                keys[r][c] = (word[round * nb + c] >> ((3 - r) * 8)) & 0xFF

        return keys
    def convert_toBytes(self, matrix): # from input matrix (state or keys matrix)
        bit = 0
        for c in range(4):
            for r in range(4):
                bit = (bit << 8) + matrix[r][c]
                
        return bit

    def cipher(self, input, key, nk, nr, bit_len):
        
        file = open("output.txt", "a")

        if bit_len == 128:
            file.write("C.1   AES-128 (Nk=4, Nr=10)\n")
        elif bit_len == 192:
            file.write("C.2   AES-192 (Nk=6, Nr=12)\n")
        elif bit_len == 256:
            file.write("C.3   AES-256 (Nk=8, Nr=14)\n")
        file.write('\n')

        # Use for addRoundKey() below
        word = self.keyExpansion(key, nk, nr)
        
        # At the start of the Cipher, the input is copied to the State array
        state = self.convert_toMatrix(input)

        # An initial Round Key addition
        state = self.addRoundKey(state, word, 0)

      
        file.write(f'PLAINTEXT:\t\t\t{self.trim_0x(input)}\n')
        file.write(f'KEY:\t\t\t\t{self.trim_0x(key)}\n')
        file.write('\n')

        # Initial input
        file.write(f'CIPHER (ENCRYPT):\n')
        file.write(f'round[ 0].input\t\t{self.trim_0x(input)}\n')
        file.write(f'round[ 0].k_sch\t\t000102030405060708090a0b0c0d0e0f\n')
        
        
        #for round = 1 step 1 to Nr-1
        for round in range (1, nr):
            
            file.write(f'round[{round: >2}].start\t\t{self.trim_0x(self.convert_toBytes(state))}\n')
            
            state = self.subBytes(state)
            file.write(f'round[{round: >2}].s_box\t\t{self.trim_0x(self.convert_toBytes(state))}\n')
            
            state = self.shiftRows(state)
            file.write(f'round[{round: >2}].s_row\t\t{self.trim_0x(self.convert_toBytes(state))}\n')

            state = self.mixColumn(state)
            file.write(f'round[{round: >2}].m_col\t\t{self.trim_0x(self.convert_toBytes(state))}\n')


            keys = self.keys(word, round)
            byte = self.convert_toBytes(keys)
            file.write(f'round[{round: >2}].k_sch\t\t{self.trim_0x(byte)}\n')

            state = self.addRoundKey(state, word, round)

        file.write(f'round[{nr}].start\t\t{self.trim_0x(self.convert_toBytes(state))}\n')

        state = self.subBytes(state)
        file.write(f'round[{nr}].s_box\t\t{self.trim_0x(self.convert_toBytes(state))}\n')
        
        state = self.shiftRows(state)
        file.write(f'round[{nr}].s_row\t\t{self.trim_0x(self.convert_toBytes(state))}\n')
        
        state = self.addRoundKey(state, word, nr)

        keys = self.keys(word, nr)
        byte = self.convert_toBytes(keys)
        file.write(f'round[{nr}].k_sch\t\t{self.trim_0x(byte)}\n')
        
        output = self.trim_0x(self.convert_toBytes(state))
        file.write(f'round[{nr}].output\t{self.trim_0x(self.convert_toBytes(state))}\n')
        file.write('\n')

        file.close()
        return output

if __name__ == "__main__":
    aes = AES()
    arr = Array()
    a = unitTestArray()

    w = aes.keyExpansion(0x2b7e151628aed2a6abf7158809cf4f3c, 4, 10)

    testInput = 0x3243f6a8885a308d313198a2e0370734
    inputState = aes.convert_toMatrix(testInput)

    aes.addRoundKey(inputState, w, 0)

    aes.cipher(0x00112233445566778899aabbccddeeff, 0x000102030405060708090a0b0c0d0e0f, 4, 10, 128 )
    aes.cipher(0x00112233445566778899aabbccddeeff, 0x000102030405060708090a0b0c0d0e0f1011121314151617, 6, 12, 192 )
    aes.cipher(0x00112233445566778899aabbccddeeff, 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f, 8, 14, 256 )
