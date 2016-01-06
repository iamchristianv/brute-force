#!/usr/bin/python

import hashlib
import itertools
import time
import os


def show_prompt():
    while True:
        command = raw_input("\nbrute-force> ")
        arguments = command.split()
        if command.lower() == "quit":
            break
        elif command.lower() == "help":
            show_help()
        elif len(arguments) != 3:
            print("- command not recognized")
            print("- use command 'help' for information on available commands")
        elif arguments[0].lower() == "encrypt":
            if not error_check(arguments):
                encrypt(arguments)
        elif arguments[0].lower() == "decrypt":
            if not error_check(arguments):
                decrypt(arguments)
        else:
            print("- command not recognized")
            print("- use command 'help' for information on available commands")


def show_help():
    print("\nCOMMANDS\t\tDESCRIPTIONS")
    print("encrypt -[hash] [file]\tencrypts words entered by user with selected hash to selected file")
    print("\t\t\tEXAMPLE: encrypt -md5 hashes.txt\n")
    print("decrypt -[hash] [file]\tdecrypts hashes provided by user with selected hash from selected file")
    print("\t\t\tEXAMPLE: decrypt -sha256 hashes.txt\n")
    print("help\t\t\tshows information on available commands\n")
    print("quit\t\t\texits out of the program\n\n")
    print("HASHES")
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
        if overwrite.lower() not in ("yes", "y"):
            return
    passwords = raw_input("\nEnter a list of passwords separated by commas below:\n")
    passwords = passwords.split()
    passwords = "".join(passwords)
    passwords = passwords.split(",")
    document = open(arguments[2], "w")
    for password in passwords:
        document.write(compute_hash(arguments[1], password) + "\n")
    document.flush()
    document.close()
    print("\nAll passwords were encrypted with " + arguments[1][1:].upper() + " and written to " + arguments[2])


def decrypt(arguments):
    if not os.path.isfile(arguments[2]):
        print("\n" + arguments[2] + " does not exist in the current working directory")
        return
    hashes = []
    document = open(arguments[2], "r")
    for line in document:
        if line.endswith("\n"):
            line = line[:-1]
        hashes.append(line)
    characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 !\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"
    start_time = time.time()
    for length in range(1, 10):
        for character in itertools.product(characters, repeat=length):
            text = "".join(character)
            computed_hash = compute_hash(arguments[1], text)
            if computed_hash in hashes:
                print("\nPassword: " + text)
                print("Hash: " + computed_hash)
                print("Duration: " + compute_duration(int(time.time() - start_time)))
                hashes.remove(computed_hash)
            if len(hashes) == 0:
                break
        if len(hashes) == 0:
            break
    print("\nAll hashes from " + arguments[2] + " were decrypted with " + arguments[1][1:].upper())


def compute_hash(hash_function, text):
    if hash_function == "-md5":
        return hashlib.md5(text).hexdigest()
    elif hash_function == "-sha1":
        return hashlib.sha1(text).hexdigest()
    elif hash_function == "-sha224":
        return hashlib.sha224(text).hexdigest()
    elif hash_function == "-sha256":
        return hashlib.sha256(text).hexdigest()
    elif hash_function == "-sha384":
        return hashlib.sha384(text).hexdigest()
    elif hash_function == "-sha512":
        return hashlib.sha512(text).hexdigest()
    else:
        return "incomplete hash"


def compute_duration(seconds):
    hours = seconds / 60/ 60 % 60
    minutes = seconds / 60 % 60
    seconds %= 60
    return str(hours) + " hour(s), " + str(minutes) + " minute(s), " + str(seconds) + " second(s)"


def main():
    show_prompt()


if __name__ == "__main__":
    main()
