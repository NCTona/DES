# -*- coding: utf-8 -*-
def hex_to_bin(hex_str, pad=64):
    """Chuyển hex sang binary (mặc định 64-bit)"""
    return bin(int(hex_str, 16))[2:].zfill(pad)


def bin_to_hex(bin_str):
    """Chuyển binary sang hex (tự động căn độ dài chẵn)"""
    hex_len = (len(bin_str) + 3) // 4
    return hex(int(bin_str, 2))[2:].upper().zfill(hex_len)


def permute(bits, table):
    """Hoán vị các bit theo bảng hoán vị"""
    return ''.join([bits[i - 1] for i in table])


def left_shift(bits, n):
    """Dịch vòng trái n bit"""
    return bits[n:] + bits[:n]


def xor(a, b):
    """Phép XOR giữa hai chuỗi bit"""
    return ''.join(str(int(x) ^ int(y)) for x, y in zip(a, b))


def pkcs7_pad(data, block_size=8):
    """Padding PKCS7 cho dữ liệu (block_size tính bằng byte)"""
    pad_len = block_size - (len(data) % block_size)
    if pad_len == block_size:  # Nếu đã đúng kích thước khối, không cần padding
        pad_len = 0
    return data + bytes([pad_len] * pad_len) if pad_len > 0 else data


def pkcs7_unpad(data):
    """Gỡ padding PKCS7"""
    if not data:
        return data
    pad_len = data[-1]
    if pad_len == 0 or pad_len > 8:  # Kiểm tra padding hợp lệ
        return data
    return data[:-pad_len]


# ====================== CÁC BẢNG HOÁN VỊ DES ======================
IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

FP = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

PC1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
]

PC2 = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
]

E = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
]

S_BOX = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]

P = [
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25
]

SHIFT_SCHEDULE = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]


# ====================== CÁC HÀM CHÍNH ======================
def generate_subkeys(key):
    """Tạo 16 subkey từ khóa chính"""
    key_bin = hex_to_bin(key)
    key_pc1 = permute(key_bin, PC1)
    left = key_pc1[:28]
    right = key_pc1[28:]
    subkeys = []
    for shift in SHIFT_SCHEDULE:
        left = left_shift(left, shift)
        right = left_shift(right, shift)
        subkey = permute(left + right, PC2)
        subkeys.append(subkey)
    return subkeys


def s_box_substitution(bits):
    """Thay thế 48-bit qua 8 S-box thành 32-bit"""
    result = []
    for i in range(8):
        block = bits[i * 6:(i + 1) * 6]
        row = int(block[0] + block[5], 2)
        col = int(block[1:5], 2)
        val = S_BOX[i][row][col]
        result.append(bin(val)[2:].zfill(4))
    return ''.join(result)


def des_round(left, right, subkey):
    """Một vòng Feistel của DES"""
    right_expanded = permute(right, E)
    xor_result = xor(right_expanded, subkey)
    sbox_result = s_box_substitution(xor_result)
    p_result = permute(sbox_result, P)
    new_right = xor(left, p_result)
    return right, new_right


def des_encrypt_block(block, subkeys):
    """Mã hóa 1 block 64-bit (dạng hex)"""
    block_bin = hex_to_bin(block)
    block_ip = permute(block_bin, IP)
    left = block_ip[:32]
    right = block_ip[32:]
    for i in range(16):
        left, right = des_round(left, right, subkeys[i])
    ciphertext = permute(right + left, FP)
    return bin_to_hex(ciphertext)


def des_encrypt(plaintext_hex, key_hex):
    """Mã hóa DES, hỗ trợ plaintext hex có độ dài bất kỳ"""
    # Nếu độ dài hex lẻ, thêm '0' để làm chẵn
    if len(plaintext_hex) % 2 != 0:
        plaintext_hex += '0'

    # Chuyển hex sang bytes
    try:
        plaintext_bytes = bytes.fromhex(plaintext_hex)
    except ValueError as e:
        raise ValueError(f"Chuỗi hex không hợp lệ: {plaintext_hex}, lỗi: {str(e)}")

    # Thêm padding PKCS7 để đảm bảo độ dài là bội số của 8 byte
    data = pkcs7_pad(plaintext_bytes)

    # Tạo subkeys từ khóa
    subkeys = generate_subkeys(key_hex)

    # Mã hóa từng block 8 byte (64-bit)
    ciphertext = b''
    for i in range(0, len(data), 8):
        block = data[i:i + 8]
        block_hex = block.hex().upper()
        encrypted_block = des_encrypt_block(block_hex, subkeys)
        ciphertext += bytes.fromhex(encrypted_block)

    return ciphertext.hex().upper()


def des_decrypt_block(block, subkeys):
    """Giải mã 1 block 64-bit (dạng hex)"""
    block_bin = hex_to_bin(block)
    block_ip = permute(block_bin, IP)
    left = block_ip[:32]
    right = block_ip[32:]
    for i in range(15, -1, -1):
        left, right = des_round(left, right, subkeys[i])
    plaintext = permute(right + left, FP)
    return bin_to_hex(plaintext)


def des_decrypt(ciphertext_hex, key_hex):
    """Giải mã DES, hỗ trợ ciphertext có độ dài bất kỳ"""
    if len(ciphertext_hex) % 16 != 0:
        raise ValueError(f"Độ dài ciphertext phải là bội số của 16 ký tự hex (8 byte), nhận được {len(ciphertext_hex)}")

    subkeys = generate_subkeys(key_hex)
    decrypted_data = b''
    for i in range(0, len(ciphertext_hex), 16):
        block_hex = ciphertext_hex[i:i + 16]
        decrypted_block = des_decrypt_block(block_hex, subkeys)
        decrypted_data += bytes.fromhex(decrypted_block)

    unpadded_data = pkcs7_unpad(decrypted_data)
    return unpadded_data.hex().upper()


# ====================== TEST CHƯƠNG TRÌNH ======================
if __name__ == "__main__":
    key = "183457799B3CDFF2"  # Khóa 64-bit (8 byte)

    # Test với nhiều độ dài plaintext hex khác nhau
    test_cases = [
        "123",  # Độ dài lẻ (3)
        "1234",  # Độ dài chẵn ngắn (4)
        "0123D56789ABCDE8",  # Độ dài 8 byte (16 ký tự)
        "ABCDEF0123456789ABCDEF",  # Độ dài lớn hơn 8 byte
        "3B849AFB89074EAF8D5C465AB9836066697B60DCE605FF453363154DFDCC211D344F2898401447FD6CF4FF2F2F9654BD"
    ]

    for plaintext in test_cases:
        print(f"\nPlaintext ban đầu: {plaintext}")
        print(f"Key: {key}")

        # Mã hóa
        ciphertext = des_encrypt(plaintext, key)
        print(f"Ciphertext: {ciphertext}")

        # Giải mã
        decrypted_text = des_decrypt(ciphertext, key)
        print(f"Plaintext sau giải mã: {decrypted_text}")

        # Kiểm tra (đối với độ dài lẻ, plaintext sẽ có '0' thêm vào)
        expected = plaintext if len(plaintext) % 2 == 0 else plaintext + '0'
        assert decrypted_text == expected, f"Giải mã không khớp! Expected {expected}, got {decrypted_text}"
        print("✅ Giải mã thành công!")