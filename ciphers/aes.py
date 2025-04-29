from random import randint
from typing import List


class AES:
    Nb = 4  # количество столбцов в тексте
    Nk = 4  # количество столбцов в ключе
    Nr = 10  # количество раундов
    SBOX = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    ]  # для повышения безопасности (когда в символе много 0 или 1 подряд)
    INV_SBOX = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    ]  # обратный sbox
    RCON = [[0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36],
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
            ]  # для уникальности раундовых ключей

    # блок методов для умножения в GF(2^8); используется только умножение на 2, 3, 9, b, d, e
    @staticmethod
    def __mul_by_02(num: int) -> int:
        if num < 0x80:
            res = (num << 1)
        else:
            res = (num << 1) ^ 0x1b
        return res % 0x100

    @staticmethod
    def __mul_by_03(num: int) -> int:
        return AES.__mul_by_02(num) ^ num

    @staticmethod
    def __mul_by_09(num: int) -> int:
        return AES.__mul_by_02(AES.__mul_by_02(AES.__mul_by_02(num))) ^ num

    @staticmethod
    def __mul_by_0b(num: int) -> int:
        return AES.__mul_by_02(AES.__mul_by_02(AES.__mul_by_02(num))) ^ AES.__mul_by_02(num) ^ num

    @staticmethod
    def __mul_by_0d(num: int) -> int:
        return AES.__mul_by_02(AES.__mul_by_02(AES.__mul_by_02(num))) ^ AES.__mul_by_02(AES.__mul_by_02(num)) ^ num

    @staticmethod
    def __mul_by_0e(num: int) -> int:
        return (AES.__mul_by_02(AES.__mul_by_02(AES.__mul_by_02(num))) ^
                AES.__mul_by_02(AES.__mul_by_02(num)) ^ AES.__mul_by_02(num))

    @staticmethod
    def __key_expansion(key: List[int]) -> List[List[int]]:
        key_data = key
        if len(key_data) < 16:  # заполнение до 16 байт
            empty_spaces = 16 - len(key_data)
            for i in range(empty_spaces):
                key_data.append(1)
        key_schedule = [[0] * AES.Nk for _ in range(4)]
        for i in range(4):  # формируем ключ в виде матрицы 4 x nk
            for j in range(AES.Nk):
                key_schedule[i][j] = key_data[i + 4 * j]
        for col in range(AES.Nk, AES.Nb * (AES.Nr + 1)):
            if col % AES.Nk == 0:
                # сдвиг в колонке
                tmp = [key_schedule[row][col - 1] for row in range(1, 4)]
                tmp.append(key_schedule[0][col - 1])
                for j in range(4):  # применяем sbox
                    tmp[j] = AES.SBOX[tmp[j]]
                for row in range(4):  # генерация нового раундового ключа
                    key_schedule[row].append(key_schedule[row][col - AES.Nk] ^ tmp[row] ^ AES.RCON[row][col // AES.Nk - 1])
            else:  # раундовый ключ пока рано генерировать
                for row in range(4):
                    key_schedule[row].append(key_schedule[row][col - AES.Nk] ^ key_schedule[row][col - 1])
        return key_schedule

    @staticmethod
    def __add_round_key(state: List[List[int]], key_schedule: List[List[int]], round_num: int = 0) -> List[List[int]]:
        for row in range(4):
            for col in range(AES.Nk):
                state[row][col] ^= key_schedule[row][round_num * AES.Nk + col]
        return state

    @staticmethod
    def __sub_bytes(state: List[List[int]], inv: bool = False) -> List[List[int]]:
        box = AES.INV_SBOX if inv else AES.SBOX  # inv for decryption
        for i in range(4):
            for j in range(AES.Nb):
                state[i][j] = box[state[i][j]]
        return state

    @staticmethod
    def __shift_rows(state: List[List[int]], inv: bool = False) -> List[List[int]]:
        if inv:
            for i in range(1, 4):
                state[i] = state[i][-i:] + state[i][:-i]
        else:
            for i in range(1, 4):
                state[i] = state[i][i:] + state[i][:i]
        return state

    @staticmethod
    def __mix_columns(state: List[List[int]], inv: bool = False) -> List[List[int]]:
        for i in range(4):
            if inv:
                s0 = (AES.__mul_by_0e(state[0][i]) ^ AES.__mul_by_0b(state[1][i]) ^ AES.__mul_by_0d(state[2][i]) ^
                      AES.__mul_by_09(state[3][i]))
                s1 = (AES.__mul_by_09(state[0][i]) ^ AES.__mul_by_0e(state[1][i]) ^ AES.__mul_by_0b(state[2][i]) ^
                      AES.__mul_by_0d(state[3][i]))
                s2 = (AES.__mul_by_0d(state[0][i]) ^ AES.__mul_by_09(state[1][i]) ^ AES.__mul_by_0e(state[2][i]) ^
                      AES.__mul_by_0b(state[3][i]))
                s3 = (AES.__mul_by_0b(state[0][i]) ^ AES.__mul_by_0d(state[1][i]) ^ AES.__mul_by_09(state[2][i]) ^
                      AES.__mul_by_0e(state[3][i]))
            else:
                s0 = AES.__mul_by_02(state[0][i]) ^ AES.__mul_by_03(state[1][i]) ^ state[2][i] ^ state[3][i]
                s1 = state[0][i] ^ AES.__mul_by_02(state[1][i]) ^ AES.__mul_by_03(state[2][i]) ^ state[3][i]
                s2 = state[0][i] ^ state[1][i] ^ AES.__mul_by_02(state[2][i]) ^ AES.__mul_by_03(state[3][i])
                s3 = AES.__mul_by_03(state[0][i]) ^ state[1][i] ^ state[2][i] ^ AES.__mul_by_02(state[3][i])
            state[0][i] = s0
            state[1][i] = s1
            state[2][i] = s2
            state[3][i] = s3
        return state

    @staticmethod
    def __prepare_state(text: List[int]) -> List[List[int]]:
        state = [[0] * AES.Nb for _ in range(4)]
        for i in range(4):  # формирование текста в виде матрицы 4 x nb
            for j in range(AES.Nb):
                state[i][j] = text[i + 4 * j]
        return state

    @staticmethod
    def __encrypt(text: List[int], password: List[int]) -> List[int]:
        state = AES.__prepare_state(text)
        key_schedule = AES.__key_expansion(password)  # генерация раундовых ключей
        state = AES.__add_round_key(state, key_schedule)
        for round_num in range(1, AES.Nr):
            state = AES.__sub_bytes(state)  # применение sbox
            state = AES.__shift_rows(state)  # сдвиг строк
            state = AES.__mix_columns(state)  # смешивание колонок (умножение матриц GF(2^8))
            state = AES.__add_round_key(state, key_schedule, round_num)  # применение раундового ключа
        # финальный раунд
        state = AES.__sub_bytes(state)
        state = AES.__shift_rows(state)
        state = AES.__add_round_key(state, key_schedule, AES.Nr)
        output = [0] * (4 * AES.Nb)
        for i in range(4):
            for j in range(AES.Nb):
                output[i + 4 * j] = state[i][j]
        return output

    @staticmethod
    def __decrypt(text: List[int], password: List[int]) -> List[int]:
        state = AES.__prepare_state(text)
        key_schedule = AES.__key_expansion(password)
        state = AES.__add_round_key(state, key_schedule, AES.Nr)
        round_num = AES.Nr - 1
        while round_num >= 1:  # раунды идут в обратном порядке
            state = AES.__shift_rows(state, True)
            state = AES.__sub_bytes(state, True)
            state = AES.__add_round_key(state, key_schedule, round_num)
            state = AES.__mix_columns(state, True)
            round_num -= 1
        state = AES.__shift_rows(state, True)
        state = AES.__sub_bytes(state, True)
        state = AES.__add_round_key(state, key_schedule, 0)
        output = [0] * (4 * AES.Nb)
        for i in range(4):
            for j in range(AES.Nb):
                output[i + 4 * j] = state[i][j]
        return output

    @staticmethod
    def __cbc_encrypt(text: List[int], key: List[int], initialization_vector: List[int]) -> List[int]:
        text_blocks = []
        for i in range(0, len(text), 16):
            text_blocks.append(text[i:i + 16])
        if len(text_blocks[-1]) < 16:
            empty_spaces = 16 - len(text_blocks[-1])
            for i in range(empty_spaces - 1):
                text_blocks[-1].append(0)
            text_blocks[-1].append(1)
        encrypted_data = []
        additional_vector = initialization_vector
        for block in text_blocks:
            block = [(block[i] ^ additional_vector[i]) for i in range(16)]
            tmp_result = AES.__encrypt(block, key)
            encrypted_data.extend(tmp_result)
            additional_vector = tmp_result
        return encrypted_data

    @staticmethod
    def __cbc_decrypt(text: List[int], key: List[int], initialization_vector: List[int]) -> List[int]:
        data_blocks = []
        for i in range(0, len(text), 16):
            data_blocks.append(text[i:i + 16])
        decrypted_data = []
        additional_vector = initialization_vector
        for block in data_blocks:
            tmp_result = AES.__decrypt(block, key)
            tmp_result = [(tmp_result[i] ^ additional_vector[i]) for i in range(16)]
            decrypted_data.extend(tmp_result)
            additional_vector = block
        return decrypted_data

    @staticmethod
    def __prepare_message(text: str, key: str, initialization_vector: str):
        text = [ord(i) for i in text]
        key = [ord(i) for i in key]
        initialization_vector = [ord(i) for i in initialization_vector]
        if len(initialization_vector) < 16:  # заполнение до 16 байт
            empty_spaces = 16 - len(initialization_vector)
            for i in range(empty_spaces):
                initialization_vector.append(1)
        return text, key, initialization_vector

    @staticmethod
    def encrypy_message(text: str, key: str, initialization_vector: str):
        text, key, initialization_vector = AES.__prepare_message(text, key, initialization_vector)
        encrypted_data = AES.__cbc_encrypt(text, key, initialization_vector)
        encrypted_data = ''.join(chr(i) for i in encrypted_data)
        return encrypted_data

    @staticmethod
    def decrypt_message(data: str, key: str, initialization_vector: str):
        data, key, initialization_vector = AES.__prepare_message(data, key, initialization_vector)
        decrypted_data = AES.__cbc_decrypt(data, key, initialization_vector)
        decrypted_data = ''.join(chr(i) for i in decrypted_data if i >= 32)
        return decrypted_data

    @staticmethod
    def generate_key(length: int) -> List[int]:
        key = []
        for _ in range(length):
            key.append(randint(0, 127))
        return key