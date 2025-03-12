#!/usr/bin/env python3

'''
Python implementation of OpenSSL's

    void DES_string_to_key(const char *str, DES_cblock *key);
'''
import sys
from Cryptodome.Cipher import DES

def odd_parity(b):
	## The least significant bit is the parity bit, which we must 
	## calculate.
	msb7 = b & 0xfe
	cnt = msb7.bit_count()
	if cnt & 1:
		## Already odd parity.
		return msb7
	
	## Set parity bit so the number of one bits is odd.
	return msb7 | 1

def DES_string_to_key(string, as_hex=False):
	if isinstance(string, bytes):
		## Already a bytes object, no conversion needed.
		input = string
	elif isinstance(string, bytearray):
		input = bytes(string)
	elif isinstance(string, str):
		input = string.encode("utf-8")
	else:
		raise ValueError("Unsupported input type")

	## A DES key is 8 octets (64 bits).
	key = bytearray(b'\x00') * 8
	
	for i,j in enumerate(input):
		if i % 16 < 8:
			key[i % 8] ^= (j << 1) & 0xff
		else:
			j = ((j << 4) & 0xf0) | ((j >> 4) & 0x0f)
			j = ((j << 2) & 0xcc) | ((j >> 2) & 0x33)
			j = ((j << 1) & 0xaa) | ((j >> 1) & 0x55)
			key[7 - (i % 8)] ^= j
	
	for i,j in enumerate(key):
		key[i] = odd_parity(j)
	
	cipher = DES.new(key=bytes(key), mode=DES.MODE_CBC, iv=key)
	if len(input) % 8 == 0:
		## No padding necessary.
		padded_input = input
	else:
		num_missing_bytes = 8 - (len(input) % 8)
		padded_input = input + (b'\x00' * num_missing_bytes)
	## The last DES block contains the key.
	key = bytearray(cipher.encrypt(padded_input)[-8:])
	
	for i,j in enumerate(key):
		key[i] = odd_parity(j)
	
	if not as_hex:
		return bytes(key)

	key_hex = ''
	for i,j in enumerate(key):
		key_hex += f"{j:02x}"
	return key_hex

if __name__ == '__main__':
	if len(sys.argv) == 1
		input = sys.stdin.read()
	else:
		input = sys.argv[1]
	print(DES_string_to_key(input, as_hex=True))
