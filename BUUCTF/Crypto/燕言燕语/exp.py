
mess = '79616E7A69205A4A517B78696C7A765F6971737375686F635F73757A6A677D20'
i = 0
flag = ''
while i*2 < len(mess):
    flag += chr(int(mess[i*2:i*2+2], 16))
    i += 1

print(flag)

'''
输出结果：
yanzi ZJQ{xilzv_iqssuhoc_suzjg}

所以应该从这里看出这是个维吉尼亚密码，密钥是yanzi（有一说一，反正我第一次是看不出的）
'''

