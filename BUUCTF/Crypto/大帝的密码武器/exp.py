c1 = 'FRPHEVGL'
# for i in range(1, 26):
#     tmpM = ''
#     for c in c1:
#         tmp = ord(c)+i
#         if tmp > 90:
#             tmp -= 26
#         tmpM += chr(tmp)
#     print(tmpM)

m1 = 'SECURITY'

ans = 'comechina'
offset = ord('S') - ord('F')

ansCipher = ''
for c in ans:
    tmp = ord(c) + offset
    if tmp > 122:
        tmp -= 26
    ansCipher += chr(tmp)

print('flag{'+ansCipher+'}')