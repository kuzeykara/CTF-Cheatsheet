# Encryption Techniques

## RSA

RSA works on the principle of *asymmetric cryptography*, meaning it uses two different keys: a **Public Key** to encrypt data and a **Private Key** to decrypt it. It relies on the mathematical relationship between prime numbers.

### Step 1: Key Generation

**Choose Primes**: Select two distinct large prime numbers, p and q.

**Calculate Modulus (n)**: *n = p x q*

**Calculate Totient (ϕ(n))**: *ϕ(n) = (p−1)×(q−1)*

**Choose Public Exponent (e)**: Select a number e such that *1<\e<ϕ(n)* and e is coprime to *ϕ(n)*. This becomes the encryption key.

**Calculate Private Exponent (d)**: Calculate d so that it satisfies the congruence relation: *d×e ≡ 1(modϕ(n))*
This means d is the modular multiplicative inverse of e.

**The Result**: Public Key: (e,n), Private Key: (d,n)

### Step 2: Encryption

To send a message M (represented as a number), the sender uses the recipient's **Public Key** (e,n) to calculate the Ciphertext C: *C = M^e(mod n)*

### Step 3: Decryption
To read the message, the recipient uses their **Private Key** (d,n) to calculate M back from C: *M = C^d (mod n)*