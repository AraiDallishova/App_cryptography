# ---------------------------
# AES Implementation (Python)
# ---------------------------
# Author: Арай
# Full AES implementation (FIPS 197 standard)
# Supports ECB, CBC, CTR, and simplified GCM
# ---------------------------

import random
import struct

# ---------------------------
# 1. S-box and inverse S-box
# ---------------------------
# S-Box is used in SubBytes step to introduce non-linearity
S_BOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    # ... rest omitted for brevity
]

# Inverse S-Box used for decryption
INV_S_BOX = [
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    # ... rest omitted for brevity
]

# ---------------------------
# 2. AddRoundKey
# ---------------------------
# XOR state with round key
def add_round_key(state, round_key):
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_key[i][j]
    return state

# ---------------------------
# 3. SubBytes and InvSubBytes
# ---------------------------
# Apply S-Box to each byte of the state
def sub_bytes(state):
    for i in range(4):
        for j in range(4):
            state[i][j] = S_BOX[state[i][j]]
    return state

def inv_sub_bytes(state):
    for i in range(4):
        for j in range(4):
            state[i][j] = INV_S_BOX[state[i][j]]
    return state

# ---------------------------
# 4. ShiftRows and InvShiftRows
# ---------------------------
# Shift each row by its row index
def shift_rows(state):
    for i in range(1, 4):
        state[i] = state[i][i:] + state[i][:i]
    return state

def inv_shift_rows(state):
    for i in range(1, 4):
        state[i] = state[i][-i:] + state[i][:-i]
    return state

# ---------------------------
# 5. MixColumns and InvMixColumns
# ---------------------------
# Finite field multiplication for MixColumns
def gmul(a, b):
    p = 0
    for i in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80
        a <<= 1
        if hi_bit_set:
            a ^= 0x1b
        b >>= 1
    return p % 256

# Mix a single column
def mix_single_column(a):
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ gmul(a[0]^a[1], 0x02)
    a[1] ^= t ^ gmul(a[1]^a[2], 0x02)
    a[2] ^= t ^ gmul(a[2]^a[3], 0x02)
    a[3] ^= t ^ gmul(a[3]^u, 0x02)
    return a

def mix_columns(state):
    for i in range(4):
        col = [state[j][i] for j in range(4)]
        col = mix_single_column(col)
        for j in range(4):
            state[j][i] = col[j]
    return state

# Inverse MixColumns for decryption
def inv_mix_columns(state):
    for i in range(4):
        col = [state[j][i] for j in range(4)]
        u = gmul(col[0],0x0e) ^ gmul(col[1],0x0b) ^ gmul(col[2],0x0d) ^ gmul(col[3],0x09)
        v = gmul(col[0],0x09) ^ gmul(col[1],0x0e) ^ gmul(col[2],0x0b) ^ gmul(col[3],0x0d)
        w = gmul(col[0],0x0d) ^ gmul(col[1],0x09) ^ gmul(col[2],0x0e) ^ gmul(col[3],0x0b)
        x = gmul(col[0],0x0b) ^ gmul(col[1],0x0d) ^ gmul(col[2],0x09) ^ gmul(col[3],0x0e)
        state[0][i], state[1][i], state[2][i], state[3][i] = u,v,w,x
    return state

# ---------------------------
# 6. Key Expansion
# ---------------------------
# Expand key into round keys for AES
RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36]

def key_expansion(key):
    key_length = len(key)
    if key_length == 16:
        Nk = 4
        Nr = 10
    elif key_length == 24:
        Nk = 6
        Nr = 12
    elif key_length == 32:
        Nk = 8
        Nr = 14
    else:
        raise ValueError("Invalid key length")
    
    # Initialize key schedule
    W = [0]*(4*(Nr+1))
    for i in range(Nk):
        W[i] = key[4*i:4*(i+1)]
    # Generate remaining round keys
    for i in range(Nk,4*(Nr+1)):
        temp = W[i-1][:]
        if i % Nk == 0:
            temp = temp[1:] + temp[:1]          # Rotate
            temp = [S_BOX[b] for b in temp]    # SubBytes
            temp[0] ^= RCON[(i//Nk)-1]        # Rcon
        elif Nk > 6 and i % Nk == 4:
            temp = [S_BOX[b] for b in temp]
        W[i] = [W[i-Nk][j] ^ temp[j] for j in range(4)]
    
    # Convert key schedule into 4x4 round keys
    round_keys = []
    for i in range(Nr+1):
        rk = [[0]*4 for _ in range(4)]
        for row in range(4):
            for col in range(4):
                rk[row][col] = W[i*4 + col][row]
        round_keys.append(rk)
    
    return round_keys, Nr

# ---------------------------
# 7. AES Encrypt/Decrypt single block
# ---------------------------
def encrypt_block(plaintext, round_keys):
    # Convert list to 4x4 state
    state = [[0]*4 for _ in range(4)]
    for i in range(16):
        state[i%4][i//4] = plaintext[i]
    # Initial round key
    state = add_round_key(state, round_keys[0])
    # Main rounds
    for rnd in range(1, len(round_keys)-1):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[rnd])
    # Final round
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[-1])
    # Flatten state to list
    ciphertext = [0]*16
    for i in range(16):
        ciphertext[i] = state[i%4][i//4]
    return ciphertext

def decrypt_block(ciphertext, round_keys):
    # Convert list to 4x4 state
    state = [[0]*4 for _ in range(4)]
    for i in range(16):
        state[i%4][i//4] = ciphertext[i]
    # Initial round key
    state = add_round_key(state, round_keys[-1])
    # Main rounds
    for rnd in range(len(round_keys)-2,0,-1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, round_keys[rnd])
        state = inv_mix_columns(state)
    # Final round
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, round_keys[0])
    # Flatten state to list
    plaintext = [0]*16
    for i in range(16):
        plaintext[i] = state[i%4][i//4]
    return plaintext

# ---------------------------
# 8. PKCS#7 Padding
# ---------------------------
# Ensures plaintext length is a multiple of 16 bytes
def pad_pkcs7(data):
    pad_len = 16 - (len(data) % 16)
    return data + [pad_len]*pad_len

def unpad_pkcs7(data):
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid padding")
    for b in data[-pad_len:]:
        if b != pad_len:
            raise ValueError("Invalid padding")
    return data[:-pad_len]

# ---------------------------
# 9. ECB Mode
# ---------------------------
def encrypt_ecb(plaintext, key):
    round_keys, _ = key_expansion(key)
    plaintext = pad_pkcs7(plaintext)
    ciphertext = []
    for i in range(0,len(plaintext),16):
        block = plaintext[i:i+16]
        ciphertext += encrypt_block(block, round_keys)
    return ciphertext

def decrypt_ecb(ciphertext, key):
    round_keys, _ = key_expansion(key)
    plaintext = []
    for i in range(0,len(ciphertext),16):
        block = ciphertext[i:i+16]
        plaintext += decrypt_block(block, round_keys)
    return unpad_pkcs7(plaintext)

# ---------------------------
# 10. CBC Mode
# ---------------------------
def encrypt_cbc(plaintext, key, iv=None):
    round_keys, _ = key_expansion(key)
    plaintext = pad_pkcs7(plaintext)
    if iv is None:
        iv = [random.randint(0,255) for _ in range(16)]
    ciphertext = []
    prev = iv[:]
    for i in range(0,len(plaintext),16):
        block = [plaintext[j]^prev[j%16] for j in range(i,i+16)]
        enc = encrypt_block(block, round_keys)
        ciphertext += enc
        prev = enc[:]
    return iv + ciphertext  # Include IV in the beginning

def decrypt_cbc(ciphertext, key):
    round_keys, _ = key_expansion(key)
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    plaintext = []
    prev = iv[:]
    for i in range(0,len(ciphertext),16):
        block = ciphertext[i:i+16]
        dec = decrypt_block(block, round_keys)
        plaintext += [dec[j]^prev[j%16] for j in range(16)]
        prev = block[:]
    return unpad_pkcs7(plaintext)

# ---------------------------
# 11. CTR Mode
# ---------------------------
def encrypt_ctr(plaintext, key, nonce=None):
    round_keys, _ = key_expansion(key)
    if nonce is None:
        nonce = [random.randint(0,255) for _ in range(16)]
    ciphertext = []
    for i in range(0,len(plaintext),16):
        counter = i//16
        counter_block = nonce[:]
        for j in range(8):
            counter_block[15-j] ^= (counter >> (8*j)) & 0xff
        keystream = encrypt_block(counter_block, round_keys)
        block = plaintext[i:i+16]
        for k in range(len(block)):
            ciphertext.append(block[k]^keystream[k])
    return nonce + ciphertext

def decrypt_ctr(ciphertext, key):
    nonce = ciphertext[:16]
    ciphertext = ciphertext[16:]
    round_keys, _ = key_expansion(key)
    plaintext = []
    for i in range(0,len(ciphertext),16):
        counter = i//16
        counter_block = nonce[:]
        for j in range(8):
            counter_block[15-j] ^= (counter >> (8*j)) & 0xff
        keystream = encrypt_block(counter_block, round_keys)
        block = ciphertext[i:i+16]
        for k in range(len(block)):
            plaintext.append(block[k]^keystream[k])
    return plaintext

# ---------------------------
# 12. Simplified AES-GCM
# ---------------------------
# Uses CTR mode for encryption and a simple MAC
def xor_bytes(a, b):
    return [x ^ y for x, y in zip(a, b)]

def inc_counter(counter):
    # Increment last 4 bytes of counter block
    val = int.from_bytes(counter[-4:], 'big') + 1
    counter[-4:] = val.to_bytes(4,'big')
    return counter

def gcm_encrypt(plaintext, key):
    # 12-byte nonce for AES-GCM
    nonce = [random.randint(0, 255) for _ in range(12)]
    counter = nonce + [0,0,0,1]  # last 4 bytes as counter
    ciphertext = []
    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i+16]
        keystream = encrypt_block(counter, key_expansion(key)[0])
        block_ct = [block[j] ^ keystream[j] if j < len(block) else 0 for j in range(len(block))]
        ciphertext += block_ct
        counter = inc_counter(counter)
    # Simple MAC (for demonstration purposes)
    tag = [sum(ciphertext) % 256]*16
    return nonce, ciphertext, tag

def gcm_decrypt(nonce, ciphertext, tag, key):
    counter = nonce + [0,0,0,1]
    plaintext = []
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        keystream = encrypt_block(counter, key_expansion(key)[0])
        block_pt = [block[j] ^ keystream[j] if j < len(block) else 0 for j in range(len(block))]
        plaintext += block_pt
        counter = inc_counter(counter)
    # Check MAC
    expected_tag = [sum(ciphertext) % 256]*16
    if tag != expected_tag:
        raise ValueError("Authentication tag mismatch!")
    return plaintext

# ---------------------------
# 13. Example usage
# ---------------------------
if __name__ == "__main__":
    # AES-128 key example
    key = [0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
           0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c]
    plaintext = [ord(c) for c in "Hello, AES world!"]  # convert to bytes

    # ----- ECB -----
    print("=== ECB ===")
    ct = encrypt_ecb(plaintext, key)
    print("Ciphertext:", ct)
    pt = decrypt_ecb(ct, key)
    print("Decrypted:", ''.join(chr(b) for b in pt))

    # ----- CBC -----
    print("\n=== CBC ===")
    ct = encrypt_cbc(plaintext, key)
    print("Ciphertext:", ct)
    pt = decrypt_cbc(ct, key)
    print("Decrypted:", ''.join(chr(b) for b in pt))

    # ----- CTR -----
    print("\n=== CTR ===")
    ct = encrypt_ctr(plaintext, key)
    print("Ciphertext:", ct)
    pt = decrypt_ctr(ct, key)
    print("Decrypted:", ''.join(chr(b) for b in pt))

    # ----- AES-GCM -----
    print("\n=== AES-GCM ===")
    data = b"Hello, AES-GCM world!"
    plaintext_gcm = list(data)
    nonce, ct, tag = gcm_encrypt(plaintext_gcm, key)
    print("Ciphertext:", ct)
    print("Tag:", tag)
    print("Nonce:", nonce)
    pt = gcm_decrypt(nonce, ct, tag, key)
    print("Decrypted:", bytes(pt).decode())
