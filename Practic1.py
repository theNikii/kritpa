##1)	написать программную реализацию одного из перечисленных ниже симметричных шифров (по выбору студента). 
# Реализация шифра должны быть выполнена студентом самостоятельно без использования готовых библиотечных функций,
#  напрямую реализующих алгоритм шифрования или его отдельные этапы. Варианты шифров:
##- Магма;
##- Кузнечик;
##- AES;

import os

# Фиксированная таблица замен (S-box)
SUBSTITUTION_TABLE = [
    [12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1],
    [6, 8, 2, 3, 9, 10, 5, 12, 1, 11, 7, 13, 0, 4, 15, 14],
    [7, 11, 5, 8, 12, 4, 2, 0, 14, 1, 3, 10, 9, 15, 6, 13],
    [13, 1, 7, 4, 11, 5, 0, 15, 3, 12, 14, 6, 9, 10, 2, 8],
    [5, 10, 15, 12, 1, 13, 14, 11, 8, 3, 6, 0, 4, 7, 9, 2],
    [14, 5, 0, 15, 13, 11, 3, 6, 9, 2, 12, 7, 1, 8, 10, 4],
    [11, 13, 12, 3, 7, 14, 10, 5, 0, 9, 4, 15, 2, 8, 1, 6],
    [15, 12, 9, 7, 3, 0, 11, 4, 1, 14, 2, 13, 6, 10, 8, 5]
]

class MagmaCipher:
    def __init__(self, key):
        self.round_keys = self.generate_round_keys(key)

    def generate_round_keys(self, key):
        keys = []
        for i in range(0, 32, 4):
            k = int.from_bytes(key[i:i+4], 'big')
            keys.append(k)
        return keys * 3 + keys[::-1]

    def g_function(self, a, k):
        t = (a + k) % (2**32)
        t = ((t << 11) | (t >> 21)) & 0xFFFFFFFF
        result = 0
        for i in range(8):
            nibble = (t >> (4 * i)) & 0xF
            subst = SUBSTITUTION_TABLE[i][nibble]
            result |= (subst << (4 * i))
        return result

    def encrypt_block(self, block):
        L = int.from_bytes(block[:4], 'big')
        R = int.from_bytes(block[4:], 'big')
        for i in range(32):
            old_R = R
            R = L ^ self.g_function(R, self.round_keys[i])
            L = old_R
        return R.to_bytes(4, 'big') + L.to_bytes(4, 'big')

    def decrypt_block(self, block):
        L = int.from_bytes(block[:4], 'big')
        R = int.from_bytes(block[4:], 'big')
        for i in range(31, -1, -1):
            old_R = R
            R = L ^ self.g_function(R, self.round_keys[i])
            L = old_R
        return R.to_bytes(4, 'big') + L.to_bytes(4, 'big')

    def process_file(self, input_file, output_file, mode):
        with open(input_file, 'rb') as f_in:
            with open(output_file, 'wb') as f_out:
                while True:
                    block = f_in.read(8)
                    if not block:
                        break
                    if len(block) < 8:
                        block += b'\x00' * (8 - len(block))
                    if mode == "encrypt":
                        result = self.encrypt_block(block)
                    else:
                        result = self.decrypt_block(block)
                    f_out.write(result)

def menu():
    print("Введите цифру для выбора: 0 - выход, 1 - шифрование, 2 - дефишрование")
    choice =  int(input())

def main():

    input_file = input("Введите путь к входному файлу: ").strip()
    output_file = input("Введите путь к выходному файлу: ").strip()
    key_hex = input("Введите ключ (256 бит в hex, 64 символа): ").strip()
    key = bytes.fromhex(key_hex)
    if len(key) != 32:
        key_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        key = bytes.fromhex(key_hex)
    choice = -1
    while True:
        menu()
        if (choice == 0):
            return 0
        if (choice == 1):
            mode = "encrypt"
            break
        if (choice == 2):
            mode = "decrypt"
            break
    
    cipher = MagmaCipher(key)
    cipher.process_file(input_file, output_file, mode)

if __name__ == "__main__":
    main()