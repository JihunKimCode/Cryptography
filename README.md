# Cryptography
I coded AES and SHA-1 in C++, and Diffie-Hellman, RSA, and SRP in Python as part of my cryptography learning. All codes were hard-coded.

## AES
For AES, I referred to [FIPS 197](https://csrc.nist.gov/pubs/fips/197/final) and [Rijndael Cipher Animation](https://formaestudio.com/rijndaelinspector/archivos/Rijndael_Animation_v4_eng-html5.html), which explained the processes thoroughly. Users can Encrypt and Decrypt using Keys of a specific size. It was challenging initially, but implementing each step in C++ turned out to be enjoyable.

## SHA-1
SHA-1 implementation in C++ followed [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final). Users can Encrypt messages. For now, it was set to run for sample texts. Its unique padding algorithm and internal function complexity made it a bit challenging, but the process was fun.

## Diffie-Hellman, RSA, and SRP
Using Miller-Rabin Algorithms and Fast Modular Exponentiation, I found two primes for Diffie-Hellman, RSA, and SRP implementation in Python. The focus was on correctly encrypting, decrypting, and decoding at each step, providing valuable insights into how each cryptography method works.

Strong prime numbers were searched using Fast modular Exponentiation and Miller-Rabin Algorithm Function. 

Use Python with version of **3.10.7 or higher** to run codes.

You may need to run `pip install pycryptodome pycryptodomex`