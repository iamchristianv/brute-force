# brute-force
A brute force program for encrypting and decrypting passwords with MD5, SHA-1, or SHA-2.

## Description
brute-force was written in Python 2.7 and is intended to be used on a command line. With brute-force and its 6
different hash functions, you can encrypt passwords to files or you can decrypt hashes from files.

Provided are two plaintext files, hashes.txt and passwords.txt, that you can use to test and run brute-force. To do so,
you can decrypt the hashes in hashes.txt and compare the results to the passwords in passwords.txt.

brute-force can decrypt hashes from passwords with commonly used characters. However, since it enumerates through each
permutation of passwords available using 96 possible characters, it takes a decent amount of time to crack passwords
that are 5 characters or fewer, and hours more to crack passwords that are 6 characters or more.

## Details
brute-force has currently only been tested with plaintext files, more specifically .txt files. Furthermore, when
decrypting hashes from a file, the hashes must be on separate lines (as with the hashes in hashes.txt) in order for
the program to parse the hashes correctly.

The character set for brute-force consists of the following:
abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 !\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~