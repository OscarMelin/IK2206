#Dictionary for key terms

##One-time pad
An encryption technique that cannot be cracked, but requires the use of a
one-time pre-shared key the same size as the message being sent. In this
technique, a plaintext is paired with a random secret key (also referred to as a
one-time pad). Then, each bit or character of the plaintext is encrypted by
combining it with the corresponding bit or character from the pad using modular
addition.

##Block cipher
In cryptography, a block cipher is a deterministic algorithm operating on
fixed-length groups of bits, called blocks, with an unvarying transformation
that is specified by a symmetric key. Block ciphers operate as important
elementary components in the design of many cryptographic protocols, and are
widely used to implement encryption of bulk data.

###Block cipher mode of operation
####Electronic codebook, ECB
The simplest of the encryption modes is the Electronic Codebook (ECB) mode. The
message is divided into blocks, and each block is encrypted separately.
####Cipher block chaining, CBC
In CBC mode, each block of plaintext is XORed with the previous ciphertext block
before being encrypted. This way, each ciphertext block depends on all plaintext
blocks processed up to that point. To make each message unique, an
initialization vector must be used in the first block.
####Block counter mode, CTR
Counter mode turns a block cipher into a stream cipher. It generates the next
keystream block by encrypting successive values of a "counter". The counter can
be any function which produces a sequence which is guaranteed not to repeat for
a long time, although an actual increment-by-one counter is the simplest and
most popular.
####Cipher feedback, CFB
A close relative of CBC, that makes a block cipher into a self-synchronizing
stream cipher. Operation is very similar; in particular, CFB decryption is
almost identical to CBC encryption performed in reverse.

##Data Encryption Standard, DES
A symmetric-key algorithm for the encryption of electronic data. Although now
considered insecure, it was highly influential in the advancement of modern
cryptography.


##Advanced Encryption Standard, AES
A specification for the encryption of electronic data established by the U.S. 
National Institute of Standards and Technology (NIST) in 2001.


##Stream cipher
