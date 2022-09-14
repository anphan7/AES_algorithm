from unitTestArray import unitTestArray
import unittest
from AES import AES
from InverseAES import Inverse
class AESTest (unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super(AESTest, self).__init__(*args, **kwargs)
        self.aes = AES()
        self.array = unitTestArray()
        self.inverse = Inverse()

    def test_ffAdd(self):
        self.assertEqual(self.aes.ffAdd(0x57, 0x83), 0xd4)
    
    
    def test_xtime(self):
        self.assertEqual(self.aes.xtime(0x57), 0xae)
        self.assertEqual(self.aes.xtime(0xae), 0x47)
        self.assertEqual(self.aes.xtime(0x47), 0x8e)
        self.assertEqual(self.aes.xtime(0x8e), 0x07)
    
    def test_ffMultiple(self):
        self.assertEqual(self.aes.ffMultiply(0x57,0x13), 0xfe)

    def test_subWord(self):
        self.assertEqual(self.aes.subWord(0x00102030), 0x63cab704)
        self.assertEqual(self.aes.subWord(0x40506070), 0x0953d051)
        self.assertEqual(self.aes.subWord(0x8090a0b0), 0xcd60e0e7)
        self.assertEqual(self.aes.subWord(0xc0d0e0f0), 0xba70e18c)

    def test_rotWord(self):
        self.assertEqual(self.aes.rotWord(0x09cf4f3c), 0xcf4f3c09 )
        self.assertEqual(self.aes.rotWord(0x2a6c7605), 0x6c76052a )

    def test_KeyExpansion(self):
        word = self.aes.keyExpansion(0x2b7e151628aed2a6abf7158809cf4f3c, 4, 10)
        self.assertEqual(word, self.array.expanded)

        # from Appendix A's table
        # 192-bit cipher key
        w = self.aes.keyExpansion(0x8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b, 6, 12)
        self.assertEqual(w[35], 0x33f0b7b3 )
        self.assertEqual(w[51], 0x01002202)

        # 256-bit cipher key
        w = self.aes.keyExpansion(0x603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4, 8, 14)
        self.assertEqual(w[43], 0x9674ee15)
        self.assertEqual(w[59], 0x706c631e)

    def test_subBytes(self):
        # Test that state == sub
        self.assertEqual(self.aes.subBytes(self.array.state), self.array.sub)

    def test_shiftRow(self):
        # Test that sub == shift
        self.assertEqual(self.aes.shiftRows(self.array.sub), self.array.shift)
    
    def test_MixCol(self):
        # Test that mix == shift
        self.assertEqual(self.aes.mixColumn(self.array.shift), self.array.mix)
    
    def test_RoundKey(self):
        w = self.aes.keyExpansion(0x2b7e151628aed2a6abf7158809cf4f3c, 4, 10)
        
        # Round 0
        input = self.aes.convert_toMatrix(0x3243f6a8885a308d313198a2e0370734)
        output = self.aes.convert_toMatrix(0x193de3bea0f4e22b9ac68d2ae9f84808)

        self.assertEqual(self.aes.addRoundKey(input, w, 0), output)

    # cipher and inverse cipher
    def test_cipher(self):
        # AES 128
        key = 0x000102030405060708090a0b0c0d0e0f

        output = self.aes.cipher(0x00112233445566778899aabbccddeeff, key, 4, 10, 128)
        self.assertEqual('0x' + output, hex(0x69c4e0d86a7b0430d8cdb78070b4c55a))
        
    
        output = self.inverse.invCipher(0x69c4e0d86a7b0430d8cdb78070b4c55a, key, 4, 10, 128)
        self.assertEqual('0x' + output, '0x00112233445566778899aabbccddeeff')
       
        # AES-192
        key = 0x000102030405060708090a0b0c0d0e0f1011121314151617
        output = self.aes.cipher(0x00112233445566778899aabbccddeeff, key, 6, 12, 192)
        self.assertEqual('0x' + output, hex(0xdda97ca4864cdfe06eaf70a0ec0d7191))

        output = self.inverse.invCipher(0xdda97ca4864cdfe06eaf70a0ec0d7191, key, 6, 12, 192)
        self.assertEqual('0x' + output, '0x00112233445566778899aabbccddeeff')


        # AES-256
        key = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
        output = self.aes.cipher(0x00112233445566778899aabbccddeeff, key, 8, 14, 256)
        self.assertEqual('0x' + output, hex(0x8ea2b7ca516745bfeafc49904b496089))

        output = self.inverse.invCipher(0x8ea2b7ca516745bfeafc49904b496089, key, 8, 14, 256)
        self.assertEqual('0x' + output, '0x00112233445566778899aabbccddeeff')


    def test_invSubByte(self):
        a = self.aes.subBytes(self.array.state)
        self.assertEqual(self.inverse.invSubBytes(a), self.array.state)


if __name__ == "__main__":
    unittest.main()

    