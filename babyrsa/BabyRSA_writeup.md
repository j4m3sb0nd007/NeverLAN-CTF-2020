
# BabyRSA

## Description

We've intercepted this RSA encrypted message 2193 1745 2164 970 1466 2495 1438 1412 1745 1745 2302 1163 2181 1613 1438 884 2495 2302 2164 2181 884 2302 1703 1924 2302 1801 1412 2495 53 1337 2217 we know it was encrypted with the following public key e: 569 n: 2533

## Solution

There is many ways to solve this challenge. How we got the encrypted message (as decimal), e and n values, i did some functions to calculate: prime numbers (to discovery value of p, q using n value); phi(n) and d, because with this information, we can decrypt the hidden message.

```python
__author__ = "J4m3s B0nd"
__copyright__ = "Copyright 2020, The Cogent Project"
__credits__ = ["Google"]
__license__ = "Apache"
__version__ = "2.0"
__maintainer__ = "J4m3s B0nd"
__email__ = "b0nd.007.j4m3s@gmail.com"

# variables given
code = [2193, 1745, 2164, 970, 1466, 2495, 1438, 1412, 1745, 1745, 2302, 1163, 2181, 1613, 1438, 884, 2495, 2302, 2164, 2181, 884, 2302, 1703, 1924, 2302, 1801, 1412, 2495, 53, 1337, 2217]
e = 569
n = 2533

# auxiliar variables
prime = []
p = 0
q = 0
flag = ""

def primeNumbers(lower, upper):
    """Return vector of prime numbers in range(lower to upper)"""
    for num in range(lower, upper + 1):
        if num > 1:
            for i in range(2, num):
                if (num % i) == 0:
                    break
            else:
                prime.append(num)

def calculatePQ(nValue):
    """Calculate the numbers of p and q"""
    global p,q
    for i in list(prime):
        for j in list(prime):
            if i==j:
                continue
            if (i*j)==nValue:
                p = i
                q = j

def xgcd(a, b):
    """return (g, x, y) such that a*x + b*y = g = gcd(a, b)"""
    x0, x1, y0, y1 = 0, 1, 1, 0
    while a != 0:
        (q, a), b = divmod(b, a), a
        y0, y1 = y1, y0 - q * y1
        x0, x1 = x1, x0 - q * x1
    return b, x0, y0

def modinv(a, b):
    """return x such that (x * a) % b == 1"""
    g, x, _ = xgcd(a, b)
    if g != 1:
        raise Exception('gcd(a, b) != 1')
    return x % b

def main():
    global flag
    primeNumbers(0, 1000)
    calculatePQ(n)

    # Compute phi(n)
    phi = (p - 1) * (q - 1)

    # Compute modular inverse of e
    d = modinv(e, phi)

    # Decrypt ciphertext
    for char in list(code):
        pt = pow(char, d, n)
        flag += chr(pt)

    print(flag)

if __name__ == "__main__":
    main()
```

## Flag

flag{sm4ll_pr1m3s_ar3_t0_e4sy}
