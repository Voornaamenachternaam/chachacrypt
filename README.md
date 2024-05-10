# chachacrypt
File encryption cli using XChaha20-Poly1305 with Argon2id in Go.


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


To encrypt a file plaintext.txt which is located in the same directory as the executable :

./chachacrypt enc -i plaintext.txt -o plaintext.txt.enc

To decrypt the ciphertext file plaintext.txt.enc :

./chachacrypt dec -i plaintext.txt.enc -o decrypted-plaintext.txt

You can also generate random passwords (give length using -s) :

./chachacrypt pw -s 15
