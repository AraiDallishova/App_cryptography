# AES Encryption Project

## Overview
This project is a full Python implementation of **AES encryption** (FIPS 197) with support for multiple modes of operation:

- **ECB (Electronic Codebook)**
- **CBC (Cipher Block Chaining)**
- **CTR (Counter)**
- **GCM (Galois/Counter Mode)** with authentication tag

It demonstrates how AES works internally using **S-box, MixColumns, ShiftRows, AddRoundKey, and key expansion**.  

The project is written in **Python 3** and does **not require external libraries**.

---

## Features
- AES-128 block cipher implementation
- Multiple modes of operation (ECB, CBC, CTR, GCM)
- PKCS#7 padding for block alignment
- Simple AES-GCM authentication (MAC tag)
- Fully commented Python code for learning purposes

---

AES Implementation Details
	•	S-box and Inverse S-box: For byte substitution
	•	ShiftRows / InvShiftRows: Row permutation
	•	MixColumns / InvMixColumns: Column mixing for diffusion
	•	AddRoundKey: XOR with round key
	•	Key Expansion: Generates round keys from the initial AES key
	•	Padding: PKCS#7 ensures plaintext aligns to 16-byte blocks

⸻

Modes of Operation
	•	ECB: Simple, insecure for repeated blocks
	•	CBC: Uses IV and chaining for better security
	•	CTR: Converts block cipher into a stream cipher
	•	GCM: Provides encryption + authentication tag
