import requests, json
from datetime import datetime, timedelta

# yeah it could be multi-threaded, but like... can't really be bothered

# https://blog.skullsecurity.org/2016/going-the-other-way-with-padding-oracles-encrypting-arbitrary-data
# https://www.youtube.com/watch?v=evrgQkULQ5U

def back_to_string(b):
    return "".join(list(map('{:02x}'.format, b)))

payload = b";admin=True;\x01" #  we wanna encrypt this
cookie_dough = [int('{:02x}'.format(i), 16) for i in payload]

endpoint_get_cookie = "http://aes.cryptohack.org/flipping_cookie/get_cookie/"
endpoint_check_admin = "http://aes.cryptohack.org/flipping_cookie/check_admin/"# <cookie>/<iv>/"

iv = "00000000000000000000000000000000"
cookie_enc = "0000000000000000000000000000000041414141414141414141414141414141"

broken_cookie = [int(cookie_enc[i:i+2], 16) for i in range(0, len(cookie_enc), 2)] # turn cookie into list

listy = [] # the bytes after decryption, before xor
listy.reverse() # easier to read
for byte in range(1, 16+1):
    print("\033[95mCALCULATING BYTE:\033[0m", byte)
    for i in range(256):
        if byte != 1:
            for j in range(1, byte): # xor all previous bytes with the current padding
                broken_cookie[(16-byte)+j] = int(listy[byte-1-j], 16) ^ byte
        broken_cookie[16-byte] = i ^ byte
        r = requests.get(endpoint_check_admin + back_to_string(broken_cookie) + "/" + iv).json()
        if "error" in r:
            if r["error"] == "Only admin can read the flag": # meaning the padding was correct
                listy.append(hex(i))
                print("\033[32mByte found:\033[0m", hex(i))
                print("Current bytes found: ", ", ".join(listy[::-1]))
                break
        hexified_broken_cookie = list(map(hex, broken_cookie))
        print("\033[96m" + hex(i) + "\033[0m", ", ".join(hexified_broken_cookie[:16]), "      ", "[" + int((i/256)*40)*"-" + (40-int((i/256)*40))*" " + "]") # fancy



xor_string = [int(i, 16) for i in listy[::-1]] # reverse listy
cut_xor_string = xor_string[16-len(cookie_dough):] # make same length from end

# do final xor with supplied string
baked_cookie = ['{:02x}'.format(cookie_dough[i] ^ cut_xor_string[i]) for i in range(len(cookie_dough))]

# formating and stuff
print("-------------------------------------------------------------------------------------------------------------------------")
print("\033[32mFinished!\033[0m")
print("Result To XOR -", back_to_string([int(i, 16) for i in listy[::-1]]))
print("Final:", "".join(baked_cookie))
print("\033[96mFinal Link:\033[0m", "\033[32m" + endpoint_check_admin + (16-len(baked_cookie))*2*"0" + "".join(baked_cookie) + cookie_enc[32:] + "/" + iv + "\033[0m")