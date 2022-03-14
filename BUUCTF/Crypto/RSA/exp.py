from gmpy2 import *

p=473398607161
q=4511491
e=17
d = invert(e, (p-1)*(q-1))
print(d)