#!/usr/bin/env python

import hashlib
import itertools
import time
import os


# shows the main menu and interprets the input from the user
def show_main_menu():
    while True:
        menu_selections = ("\n1) Encrypt Passwords", "2) Decrypt Hashes", "3) Quit Program")
        for menu_selection in menu_selections:
            print(menu_selection)
        selection = raw_input("\nSelect a menu option: ")
        if not selection.isdigit():
            print("- selection not a number")
        elif int(selection) == 1:
            encrypt()
        elif int(selection) == 2:
            decrypt()
        elif int(selection) == 3:
            break
        else:
            print("- selection not available")


# shows a menu of available hash functions and recommends one based on hashes provided by the user
def show_hash_menu(action, hashes=None):
    while True:
        hash_functions = ("\n1) MD5", "2) SHA-1", "3) SHA-224", "4) SHA-256", "5) SHA-384", "6) SHA-512", "7) Go Back")
        lengths = {"32": "MD5", "40": "SHA-1", "56": "SHA-224", "64": "SHA-256", "96": "SHA-384", "128": "SHA-512"}
        for hash_function in hash_functions:
            print(hash_function)
        if hashes is not None:
            key = str(len(hashes[0]))
            if key in lengths:
                print("Recommendation: " + lengths[key])
            else:
                print("No Recommendation")
        selection = raw_input("\nSelect a hash function to " + action + " with: ")
        if not selection.isdigit():
            print("- selection not a number")
        elif 1 <= int(selection) <= 6:
            index = int(selection) - 1
            hash_function = hash_functions[index]
            hash_function = hash_function.split()
            return hash_function[1]
        elif int(selection) == 7:
            return None
        else:
            print("- selection not available")


# lets user provide a list of passwords, then encrypts them and stores them in a file the user selected
def encrypt():
    # user enters a list of comma-separated passwords
    passwords = raw_input("\nEnter a list of passwords separated by commas (e.g. abc123,letmein,password):\n")
    passwords = passwords.split(",")
    if len(passwords) == 0:
        return
    # user provides the file to write passwords to, if it doesn't exist, it will be created
    filename = raw_input("\nEnter the name of the file to write to: ")
    if os.path.isfile(filename):
        overwrite = raw_input("\n" + filename + " already exists, would you like to overwrite it (yes/no): ")
        if overwrite.lower() not in ("yes", "y"):
            return
    # user selects the hash function to encrypt the passwords with
    hash_function = show_hash_menu("encrypt")
    if hash_function is None:
        return
    document = open(filename, "w")
    # computes hash for each password then writes them to the file
    for password in passwords:
        document.write(compute_hash(hash_function, password) + "\n")
    document.flush()
    document.close()
    print("\nAll passwords were encrypted with " + hash_function + " and written to " + filename)


# enumerates through all permutations of passwords, computes their hashes, and compares them with hashes in file
def decrypt():
    # user provides the file to read hashes from
    filename = raw_input("\nEnter the name of the file to read from: ")
    if not os.path.isfile(filename):
        print("\n" + filename + " does not exist in the current working directory")
        return
    hashes = []
    document = open(filename, "r")
    # stores the hashes locally to reference them later when enumerating through passwords
    for line in document:
        if line.endswith("\n"):
            line = line[:-1]
        hashes.append(line)
    # user selects the hash function to compute the hashes for the enumerated passwords
    hash_function = show_hash_menu("decrypt", hashes=hashes)
    if hash_function is None:
        return
    characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 !\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"
    start_time = time.time()
    # enumerates through all password permutations up to length 9 using the 96 characters provided
    for length in range(1, 10):
        for character in itertools.product(characters, repeat=length):
            text = "".join(character)
            computed_hash = compute_hash(hash_function, text)
            # checks if the computed hash matches a hash provided by the user
            if computed_hash in hashes:
                print("\nPassword: " + text)
                print("Hash: " + computed_hash)
                print("Elapsed Time: " + compute_elapsed_time(int(time.time() - start_time)))
                hashes.remove(computed_hash)
            if len(hashes) == 0:
                break
        if len(hashes) == 0:
            break
    print("\nAll hashes from " + filename + " were decrypted with " + hash_function)


# computes the hash of the text provided using the hash function passed in
def compute_hash(hash_function, text):
    if hash_function == "MD5":
        return hashlib.md5(text).hexdigest()
    elif hash_function == "SHA-1":
        return hashlib.sha1(text).hexdigest()
    elif hash_function == "SHA-224":
        return hashlib.sha224(text).hexdigest()
    elif hash_function == "SHA-256":
        return hashlib.sha256(text).hexdigest()
    elif hash_function == "SHA-384":
        return hashlib.sha384(text).hexdigest()
    elif hash_function == "SHA-512":
        return hashlib.sha512(text).hexdigest()
    else:
        return "incomplete hash"


# computes the amount of hours, minutes, and seconds from a large amount of seconds
def compute_elapsed_time(seconds):
    hours = seconds / 60/ 60 % 60
    minutes = seconds / 60 % 60
    seconds %= 60
    return str(hours) + " hour(s), " + str(minutes) + " minute(s), " + str(seconds) + " second(s)"


def main():
    show_main_menu()


if __name__ == "__main__":
    main()
