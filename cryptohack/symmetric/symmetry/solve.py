import requests, binascii

def xor(xor1, xor2):
        return bytes(a ^ b for a, b in zip(xor1, xor2))

endpoint_encrypt = "http://aes.cryptohack.org/symmetry/encrypt/" # <plaintext>/<iv>/"
endpoint_flag = "http://aes.cryptohack.org/symmetry/encrypt_flag" 

r = requests.get(endpoint_flag).json()
iv = r["ciphertext"][:32]
flag_enc = r["ciphertext"][32:]

print("IV:        ", iv, "\nCyphertext:", flag_enc)

r = requests.get(endpoint_encrypt + "00000000000000000000000000000000/" + iv).json()["ciphertext"]

cypher_stream = bytearray.fromhex(r)
flag_enc_first = bytearray.fromhex(flag_enc[:32])
flag_first = xor(cypher_stream, flag_enc_first)

print("First block:", flag_first)


r = requests.get(endpoint_encrypt + "00000000000000000000000000000000/" + binascii.hexlify(cypher_stream).decode("utf-8")).json()["ciphertext"]

cypher_stream = bytearray.fromhex(r)
flag_enc_second = bytearray.fromhex(flag_enc[32:])
flag_second = xor(cypher_stream, flag_enc_second)

print("Second Block:", flag_second)

print("Flag:\n", (flag_first + flag_second + b"}").decode("utf-8")) # idk why but it works