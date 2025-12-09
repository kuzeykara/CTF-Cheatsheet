# RSA Least Significant Bit (LSB) Oracle Attack

## 1. The Concept
The **RSA LSB Oracle Attack** (also known as a Parity Oracle Attack) allows an attacker to decrypt a message without knowing the private key. It relies on a server ("Oracle") that leaks whether a decrypted message is **Even** or **Odd**.

### The Math
1.  **RSA Basics:** Encrypting message $P$ is $C = P^e \pmod N$.
2.  **The Trick:** The attacker multiplies the ciphertext $C$ by the encrypted version of 2 ($2^e$).
    $$C' = C \cdot 2^e \pmod N = (P \cdot 2)^e \pmod N$$
3.  **The Decryption:** When the Oracle decrypts $C'$, it sees $2P \pmod N$.

### The Logic
Because $P < N$, doubling it ($2P$) results in two scenarios relative to the modulus $N$ (which is always odd):

| Scenario | Value | Parity | Deduction |
| :--- | :--- | :--- | :--- |
| **No Wrap** | $2P < N$ | **Even** | $P$ is in the **Lower Half** $[0, N/2]$ |
| **Wrap** | $2P > N$ | **Odd** | $P$ is in the **Upper Half** $[N/2, N]$ |

*(Note: If $2P$ wraps around $N$, it becomes $2P - N$. Even minus Odd equals Odd.)*

## 2. The Algorithm (Binary Search)
By repeating this process, the attacker performs a **Binary Search**, narrowing the possible range of the plaintext by 50% with every query.

1.  **Initialize:** Set bounds `[Low, High]` to `[0, N]`.
2.  **Loop:** For every bit in the modulus (e.g., 1024 times for 1024-bit RSA):
    * Multiply the ciphertext by the next power of 2 ($2^e, 4^e, 8^e...$).
    * Send to Oracle.
    * **If Even:** The plaintext is in the lower half of the current bounds. Set `High = Midpoint`.
    * **If Odd:** The plaintext is in the upper half. Set `Low = Midpoint`.
3.  **Result:** The `High` (or `Low`) bound converges on the plaintext $P$.

## 3. Python Exploit Example
This script simulates the attack; it uses the `decimal` library to handle the floating-point division required for the binary search bounds.

```python
import decimal

def perform_attack(N, e, c_target):
    print(f"[*] Target Ciphertext: {c_target}")
    print(f"[*] Modulus N: {N}")
    
    # Use Decimal for precise division of large integers
    decimal.getcontext().prec = N.bit_length()
    
    # Define the search interval [0, N]
    lower_bound = decimal.Decimal(0)
    upper_bound = decimal.Decimal(N)
    
    # We essentially encrypt '2' to multiply the ciphertext homomorphically
    multiplier = pow(2, e, N)
    
    # Current ciphertext to send to oracle
    current_c = c_target
    
    # Loop log2(N) times to recover all bits
    for i in range(N.bit_length()):
        # 1. Update ciphertext: Multiply by 2 inside the encryption
        # C_new = C_old * (2^e) % N
        current_c = (current_c * multiplier) % N
        
        # 2. Ask Oracle
        is_odd = oracle(current_c)
        
        # 3. Update Bounds
        mid = (lower_bound + upper_bound) / 2
        if is_odd:
            # Oracle says Odd -> Wrap occurred -> Upper Half
            lower_bound = mid
        else:
            # Oracle says Even -> No Wrap -> Lower Half
            upper_bound = mid

    return int(upper_bound)
```