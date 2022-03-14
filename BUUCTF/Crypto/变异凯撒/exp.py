c = 'afZ_r9VYfScOeO_UL^RWUc'
# flag = 'flag{'
# for cha in c[0:4]:
#     print(ord(cha), end=" ")
# print("\n=========")
# for m in flag:
#     print(ord(m), end=" ")

flag = ''
offset = 5
for char in c:
    flag += chr(ord(char) + offset)
    offset += 1
print(flag) 