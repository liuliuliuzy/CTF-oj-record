from gmpy2 import *
import base64

b = invert(11, 26)
def decrypt(x, inverse):
    # print(x, inverse, c_mod((x-6)*inverse, 26))
    return (x-6)*inverse % 26
cipher = 'welcylk'
raw = ''
for i in range(len(cipher)):
    num = decrypt(ord(cipher[i])-97, b)
    print(num)
    raw += chr(num+97)


print(raw)
print(base64.b64encode(raw.encode()))
