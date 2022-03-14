'''
主要是了解到了RSA公钥形式的部分知识

将pub.key在kali上分解提取n和e
运行结果：
====================================================================
└─$ openssl rsa -pubin -text -modulus -in warmup -in pubkey.txt 
RSA Public-Key: (256 bit)
Modulus:
    00:c0:33:2c:5c:64:ae:47:18:2f:6c:1c:87:6d:42:
    33:69:10:54:5a:58:f7:ee:fe:fc:0b:ca:af:5a:f3:
    41:cc:dd
Exponent: 65537 (0x10001)
Modulus=C0332C5C64AE47182F6C1C876D42336910545A58F7EEFEFC0BCAAF5AF341CCDD
writing RSA key
-----BEGIN PUBLIC KEY-----
MDwwDQYJKoZIhvcNAQEBBQADKwAwKAIhAMAzLFxkrkcYL2wch21CM2kQVFpY9+7+
/AvKr1rzQczdAgMBAAE=
-----END PUBLIC KEY-----
=====================================================================
然后注意到拿到n可以先尝试用在线工具分解
for example:

- http://www.factordb.com/

'''

from gmpy2 import *
from Crypto.Util.number import bytes_to_long, long_to_bytes

n_hex_str = 'C0332C5C64AE47182F6C1C876D42336910545A58F7EEFEFC0BCAAF5AF341CCDD'
n = mpz(int(n_hex_str, base=16))
print(n)

p = mpz(285960468890451637935629440372639283459)
q = mpz(304008741604601924494328155975272418463)

e = 65537
d = invert(e, (p-1)*(q-1))
c = bytes_to_long(b'\x41\x96\xC0\x59\x4A\x5E\x00\x0A\x96\xB8\x78\xB6\x7C\xD7\x24\x79\x5B\x13\xA8\xF2\xCA\x54\xDA\x06\xD0\xF1\x9C\x28\xBE\x68\x9B\x62')
m = powmod(c, d, n)
print(long_to_bytes(m))