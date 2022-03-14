f = open('题目.txt', mode='r')
cipher = f.readline()
flag = ''
for i in cipher:
    if ord(i) <= 122 and ord(i) >= 97:
        flag += chr(ord(i) - 13)
    else:
        flag += i
f.close()
print(cipher)
print(flag)
