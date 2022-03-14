from gmpy2 import invert, mpz, powmod

f = open('data.txt', 'r')

n = mpz(920139713)

e = 19
p = mpz(18443)
q = mpz(49891)
d = invert(e, (p-1)*(q-1))

# skip the first two lines
f.readline()
f.readline()

# m = []
flag = ''
for line in f.readlines():
    tmpc = mpz(int(line[:-1], base=10))
    tmpm = powmod(tmpc, d, n)
    # m.append(tmpm)
    flag += chr(tmpm)
f.close()

print(flag)