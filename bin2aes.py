import sys
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import hashlib

KEY = get_random_bytes(16)
iv = 16 * b'\x00'
cipher = AES.new(hashlib.sha256(KEY).digest(), AES.MODE_CBC, iv)

try:
    plaintext = open(sys.argv[1], "rb").read()
except:
    print("File argument needed! %s <raw payload file>" % sys.argv[0])
    sys.exit()

ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

# Save the encrypted bytes to a file
encrypted_file = "payload.bin"
with open(encrypted_file, "wb") as file:
    file.write(ciphertext)

print('AESkey[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in KEY) + ' };')

hex_bytes = [f'0x{x:02X}' for x in ciphertext]
num_bytes = len(ciphertext)
num_rows = (num_bytes + 15) // 16

# Print the hex bytes format with a maximum of 16 bytes per line
print(f'Shellcode in hex bytes format:')
print('payload[] = {')
for i in range(num_rows):
    row_start = i * 16
    row_end = min(row_start + 16, num_bytes)
    row_hex = ', '.join(hex_bytes[row_start:row_end])
    if i == num_rows - 1:
        # Remove the last comma for the last row
        print(f'    {row_hex}')
    else:
        print(f'    {row_hex},')
print('};')
print(f'[+] Saved encrypted file as {encrypted_file}')