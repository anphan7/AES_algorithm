
from AES import AES
from Array import Array
from unitTestArray import unitTestArray
class Inverse:
    
    def __init__(self):
        self.arr = Array()

    def invSubBytes(self, state):
        result = [[] for _ in range (4)]

        for r in range(4):
            for c in range(4):
                row = (state[r][c] & 0xF0) >> 4
                col = state[r][c] & 0xF
                result[r].append(self.arr.InvSbox[row][col])
        return result
    

    def invShiftRows(self, state):
        result = [[] for _ in range(4)]
        for row in range(4):
            result[row] = state[row][4-row:] + state[row][:4-row]
        
        return result


    def invMixcolumns(self, state):
        result = [[0,0,0,0] for _ in range(4)]
        aes = AES()
        for c in range(4):
            result[0][c] = aes.ffAdd(aes.ffAdd(aes.ffAdd(aes.ffMultiply(0x0e, state[0][c]), aes.ffMultiply(0x0b, state[1][c])), 
                            aes.ffMultiply(0x0d, state[2][c])), aes.ffMultiply(0x09, state[3][c]))
            
            result[1][c] = aes.ffAdd(aes.ffAdd(aes.ffAdd(aes.ffMultiply(0x09, state[0][c]), aes.ffMultiply(0x0e, state[1][c])), 
                            aes.ffMultiply(0x0b, state[2][c])), aes.ffMultiply(0x0d, state[3][c]))
            
            result[2][c] = aes.ffAdd(aes.ffAdd(aes.ffAdd(aes.ffMultiply(0x0d, state[0][c]),aes.ffMultiply(0x09, state[1][c])), 
                            aes.ffMultiply(0x0e, state[2][c])), aes.ffMultiply(0x0b, state[3][c]))
            
            result[3][c] = aes.ffAdd(aes.ffAdd(aes.ffAdd(aes.ffMultiply(0x0b, state[0][c]), aes.ffMultiply(0x0d, state[1][c])), 
                            aes.ffMultiply(0x09, state[2][c])), aes.ffMultiply(0x0e, state[3][c]))
        return result

    def invCipher(self, input, key, nk, nr, bit_len):
        aes = AES()
        file = open("output.txt", "a")

        # Use for addRoundKey() below
        word = aes.keyExpansion(key, nk, nr)
        
        # At the start of the Cipher, the input is copied to the State array
        state = aes.convert_toMatrix(input)

        # An initial Round Key addition
        state = aes.addRoundKey(state, word, nr)


        file.write(f'INVERSE CIPHER (DECRYPT):\n')
        file.write(f'round[ 0].iinput\t{aes.trim_0x(input)}\n')
        
        keys = aes.keys(word, nr)
        byte = aes.convert_toBytes(keys)
        file.write(f'round[ 0].ik_sch\t{aes.trim_0x(byte)}\n')


        for round in range (nr - 1, 0, -1):
            file.write(f'round[{nr - round: >2}].istart\t{aes.trim_0x(aes.convert_toBytes(state))}\n')
            state = self.invShiftRows(state)

            file.write(f'round[{nr- round: >2}].is_row\t{aes.trim_0x(aes.convert_toBytes(state))}\n')
            state = self.invSubBytes(state)

            file.write(f'round[{nr - round: >2}].is_box\t{aes.trim_0x(aes.convert_toBytes(state))}\n')
            state = aes.addRoundKey(state, word, round)

            keys = aes.keys(word, round)
            byte = aes.convert_toBytes(keys)
            file.write(f'round[{nr - round: >2}].ik_sch\t{aes.trim_0x(byte)}\n')
            file.write(f'round[{nr - round: >2}].ik_add\t{aes.trim_0x(aes.convert_toBytes(state))}\n')
            state = self.invMixcolumns(state)
        
        file.write(f'round[{nr: >2}].istart\t{aes.trim_0x(aes.convert_toBytes(state))}\n')
        state = self.invShiftRows(state)
        
        file.write(f'round[{nr: >2}].is_row\t{aes.trim_0x(aes.convert_toBytes(state))}\n')
        state = self.invSubBytes(state)

        file.write(f'round[{nr: >2}].is_box\t{aes.trim_0x(aes.convert_toBytes(state))}\n')

        keys = aes.keys(word, 0)
        byte = aes.convert_toBytes(keys)
        file.write(f'round[{nr: >2}].ik_sch\t{aes.trim_0x(byte)}\n')

        state = aes.addRoundKey(state, word, 0)
        output = aes.trim_0x(aes.convert_toBytes(state))

        file.write(f'round[{nr: >2}].ioutput\t{aes.trim_0x(aes.convert_toBytes(state))}\n')
        file.write('\n\n')
        file.close()

        return output

if __name__ == "__main__":
    aes = AES()
    i_aes = Inverse()
    u_arr = unitTestArray()
    arr = Array()

    i_aes.invCipher(0x69c4e0d86a7b0430d8cdb78070b4c55a, 0x000102030405060708090a0b0c0d0e0f, 4, 10, 128)
