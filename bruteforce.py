#!/usr/bin/python

import hashlib
import itertools
import time
import os


def show_prompt():
    while True:
        command = raw_input("\nbrute-force> ")
        arguments = command.split()
        if command == "quit":
            break
        elif command == "help":
            show_help()
        elif len(arguments) != 3:
            print("- command not recognized")
            print("- use command 'help' for information on available commands")
        elif arguments[0] == "encrypt":
            if not error_check(arguments):
                encrypt(arguments)
        elif arguments[0] == "decrypt":
            if not error_check(arguments):
                decrypt(arguments)
        else:
            print("- command not recognized")
            print("- use command 'help' for information on available commands")


def show_help():
    print("COMMAND\t\t\tDESCRIPTION")
    print("encrypt -[hash] [file]\tencrypts words entered by user with selected hash to selected file")
    print("\t\t\tEXAMPLE: encrypt -md5 hashes.txt\n")
    print("decrypt -[hash] [file]\tdecrypts hashes provided by user with selected hash from selected file")
    print("\t\t\tEXAMPLE: decrypt -sha256 hashes.txt\n")
    print("HASH OPTIONS")
    print("md5\t\tsha1\t\tsha224")
    print("sha256\t\tsha384\t\tsha512\n")


def error_check(arguments):
    if hash_check(arguments[1]):
        return True
    if file_check(arguments[2]):
        return True
    return False


def hash_check(argument):
    if argument.lower() == "-md5":
        print("md5")
    elif argument.lower() == "-sha1":
        print("sha1")
    elif argument.lower() == "-sha224":
        print("sha224")
    elif argument.lower() == "-sha256":
        print("sha256")
    elif argument.lower() == "-sha384":
        print("sha384")
    elif argument.lower() == "-sha512":
        print("sha512")
    else:
        print("- hash not recognized")
        print("- use command 'help' for information on available hashes")
        return True
    return False


def file_check(argument):
    try:
        open(argument, "a").close()
        os.unlink(argument)
    except OSError:
        print("- file not recognized")
        print("- use file with a .txt extension")
        return True
    return False


def encrypt(arguments):
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


def decrypt(arguments):
    file_name = raw_input("Enter the name of a file to read from (include .txt): ")
    if not os.path.isfile(file_name):
        print(" - " + file_name + " does not exist in the current working directory\n")
        return


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
    show_prompt()


if __name__ == "__main__":
    main()
