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
    print("\nCOMMAND\t\t\tDESCRIPTION")
    print("encrypt -[hash] [file]\tencrypts words entered by user with selected hash to selected file")
    print("\t\t\tEXAMPLE: encrypt -md5 hashes.txt\n")
    print("decrypt -[hash] [file]\tdecrypts hashes provided by user with selected hash from selected file")
    print("\t\t\tEXAMPLE: decrypt -sha256 hashes.txt\n")
    print("HASH OPTIONS")
    print("md5\t\tsha1\t\tsha224")
    print("sha256\t\tsha384\t\tsha512")


def error_check(arguments):
    if hash_check(arguments[1]):
        return True
    if file_check(arguments[2]):
        return True
    return False


def hash_check(argument):
    hashes = ("-md5", "-sha1", "-sha224", "-sha256", "-sha384", "-sha512")
    if argument.lower() not in hashes:
        print("- hash not recognized")
        print("- use command 'help' for information on available hashes")
        return True
    return False


def file_check(argument):
    try:
        if not os.path.isfile(argument):
            open(argument, "a").close()
            os.unlink(argument)
    except OSError:
        print("- file not recognized")
        print("- use file with .txt extension")
        return True
    return False


def encrypt(arguments):
    if os.path.isfile(arguments[2]):
        overwrite = raw_input("\n" + arguments[2] + " already exists, would you like to overwrite it [yes/no]: ")
        if overwrite.lower() not in ("yes", "ye", "y"):
            return
    passwords = raw_input("\nEnter a list of passwords separated by commas below:\n")
    passwords = passwords.split()
    passwords = "".join(passwords)
    passwords = passwords.split(",")
    txt_file = open(arguments[2], "w")
    for password in passwords:
        if arguments[1] == "-md5":
            txt_file.write(hashlib.md5(password).hexdigest() + "\n")
        elif arguments[1] == "-sha1":
            txt_file.write(hashlib.sha1(password).hexdigest() + "\n")
        elif arguments[1] == "-sha224":
            txt_file.write(hashlib.sha224(password).hexdigest() + "\n")
        elif arguments[1] == "-sha256":
            txt_file.write(hashlib.sha256(password).hexdigest() + "\n")
        elif arguments[1] == "-sha384":
            txt_file.write(hashlib.sha384(password).hexdigest() + "\n")
        elif arguments[1] == "-sha512":
            txt_file.write(hashlib.sha512(password).hexdigest() + "\n")
    txt_file.flush()
    txt_file.close()
    print("\nAll passwords were encrypted with " + arguments[1][1:].upper() + " and written to " + arguments[2])


def decrypt(arguments):
    if not os.path.isfile(arguments[2]):
        print("\n" + arguments[2] + " does not exist in the current working directory")
        return

    print("\nAll hashes from " + arguments[2] + " were decrypted with " + arguments[1][1:].upper())


def read_hashes()


def main():
    show_prompt()


if __name__ == "__main__":
    main()
