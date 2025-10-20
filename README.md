# ChaChacrypt
File encryption-cli using XChaha20-Poly1305 with Argon2id in Go.


**1: Install Golang** 

apt install golang -y


**2: Create chachacrypt.go**

mkdir ~/chachacrypt

cd ~/chachacrypt

nano chachacrypt.go

Paste the code from 'chachacrypt.go' in this repository into your: chachacrypt.go


**3: Build**

go mod init chachacrypt

go mod tidy

go build


**How to use chachacrypt**

The encrypted file format includes a header with cryptographic parameters (Argon2id configuration, salt, nonce size) to ensure robustness and future compatibility.

To encrypt a file `plaintext.txt` which is located in the same directory as the executable:

```bash
./chachacrypt enc -i plaintext.txt -o plaintext.txt.enc
```
You will be prompted to enter a strong password. If `plaintext.txt.enc` already exists, you will be asked for confirmation to overwrite.

To decrypt the ciphertext file `plaintext.txt.enc`:

```bash
./chachacrypt dec -i plaintext.txt.enc -o decrypted-plaintext.txt
```
You will be prompted to enter the password. If `decrypted-plaintext.txt` already exists, you will be asked for confirmation to overwrite.

You can also generate random passwords (give length using `-s`):

```bash
./chachacrypt pw -s 15
```

---

### Security Considerations (Proposal 12)

`chachacrypt` uses strong, modern cryptographic primitives:
*   **Key Derivation Function (KDF):** Argon2id is used to derive a strong encryption key from your password. It is configured with `15` iterations, `64MB` of memory, and `NumCPU()` threads (capped at 255) by default to make brute-force attacks computationally intensive (Proposal 1).
*   **Authenticated Encryption with Associated Data (AEAD):** XChaCha20-Poly1305 is used for encryption and integrity protection.

**Best Practices for Use:**
*   **Strong Passwords:** Always use strong, unique passwords. The security of your encrypted files directly depends on the strength of your password.
*   **Output Files:** The tool will prompt you before overwriting an existing output file, preventing accidental data loss.
*   **File Format:** The encrypted files now include a robust header that stores the Argon2id parameters and other necessary cryptographic details, ensuring that files can be decrypted correctly even if default parameters change in future versions.
