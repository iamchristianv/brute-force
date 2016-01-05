#!/usr/bin/python

import hashlib
import itertools
import time
import os.path


def show_menu():
    while True:
        print("1: Crack Passwords")
        print("2: Write Passwords")
        print("3: Quit")
        selection = raw_input("\nbrute-force> ")
        if not selection.isdigit():
            print("- " + selection + " is not a valid selection\n")
            continue
        if int(selection) == 1:
            crack_passwords()
        elif int(selection) == 2:
            write_passwords()
        elif int(selection) == 3:
            break
        else:
            print("- " + selection + " is not a valid selection\n")


def crack_passwords():
    file_name = raw_input("Enter the name of a file to read from (include .txt): ")
    if not os.path.isfile(file_name):
        print(" - " + file_name + " does not exist in the current working directory\n")
        return


def write_passwords():
    file_name = raw_input("\nEnter the name of a file to write to (include .txt): ")
    if os.path.isfile(file_name):
        overwrite = raw_input(file_name + " already exists, would you like to overwrite it (yes/no): ")
        if overwrite.lower() != "yes" or overwrite.lower() != "y":
            print(" - " + file_name + " was not overwritten\n")
            return
    passwords = raw_input("\nEnter your alphanumeric passwords separated by a comma:\n")
    passwords = passwords.split()
    passwords = "".join(passwords)
    passwords = passwords.split(",")
    hash_function = select_hash_function()
    txt_file = open(file_name, "w")
    for password in passwords:
        if hash_function == "MD5":
            txt_file.write(hashlib.md5(password).hexdigest() + "\n")
        elif hash_function == "SHA1":
            txt_file.write(hashlib.sha1(password).hexdigest() + "\n")
        elif hash_function == "SHA224":
            txt_file.write(hashlib.sha224(password).hexdigest() + "\n")
        elif hash_function == "SHA256":
            txt_file.write(hashlib.sha256(password).hexdigest() + "\n")
        elif hash_function == "SHA384":
            txt_file.write(hashlib.sha384(password).hexdigest() + "\n")
        elif hash_function == "SHA512":
            txt_file.write(hashlib.sha512(password).hexdigest() + "\n")
    txt_file.flush()
    txt_file.close()
    print("\nAll passwords were encrypted with " + hash_function + " and written to " + file_name + "\n")


def select_hash_function():
    while True:
        print("\n1: MD5")
        print("2: SHA1")
        print("3: SHA224")
        print("4: SHA256")
        print("5: SHA384")
        print("6: SHA512")
        selection = raw_input("\nSelect a hash function to encrypt your passwords: ")
        if not selection.isdigit():
            print("- " + selection + " is not a valid selection\n")
            continue
        if int(selection) == 1:
            return "MD5"
        elif int(selection) == 2:
            return "SHA1"
        elif int(selection) == 3:
            return "SHA224"
        elif int(selection) == 4:
            return "SHA256"
        elif int(selection) == 5:
            return "SHA384"
        elif int(selection) == 6:
            return "SHA512"
        else:
            print("- " + selection + " is not a valid selection\n")


def main():
    show_menu()


if __name__ == "__main__":
    main()
