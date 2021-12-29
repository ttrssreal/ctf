from Crypto.Util.strxor import strxor
import requests

# Bug is a typo in increment(), stup instead of step. This causes the key to be repeated.

ciphertext = bytes.fromhex(requests.get("https://aes.cryptohack.org/bean_counter/encrypt/").json()["encrypted"])
es = "89504e470d0a1a0a0000000d49484452" # One block of magic bytes and header bytes common to all png's.

key = strxor(ciphertext[:16], bytes.fromhex(es)) # Get key with known plaintext and ciphertext

last_eleven_bytes = b"\xa2&\x08\xe6\xb8\xf6\x91\x14\xff\xd3/" # as len(CT) % 16 != 0
decrypted_last_eleven = strxor(key[:11], last_eleven_bytes) # Turns out its not even needed but whatever.

with open("png.exe.png.exe.png", "wb") as f:
    i = 0
    block = ciphertext[i:i+16]
    while block:
        f.write(strxor(block, key) if len(block) == 16 else decrypted_last_eleven)
        i += 16
        block = ciphertext[i:i+16]