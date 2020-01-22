"""
- CS2911 - 0NN
- Fall 2017
- Lab N
- Names:
  -
  -

B-bit RSA
"""

import random
import sys
import math

# To change the number of bits, change BIT_LENGTH, MAX_PRIME, and MIN_PRIME.
# MAX_PRIME and MIN_PRIME should have exactly BIT_LENGTH/2 bits
BITS_PER_HEX_DIGIT = 4 # binary digits per hex digit -- always 4
BIT_LENGTH = 38  # "B" in the lab handout. Length of n in bits
HEX_LENGTH = (BIT_LENGTH+(BITS_PER_HEX_DIGIT-1))//BITS_PER_HEX_DIGIT # Length of n in hexadecimal digits
MAX_PRIME = 0b1111111111111111111  # The maximum value a prime number can have
MIN_PRIME = 0b1100000000000000001  # The minimum value a prime number can have
PUBLIC_EXPONENT = 17  # The default public exponent


def main():
    """ Provide the user with a variety of encryption-related actions """

    # Get chosen operation from the user.
    action = input("Select an option from the menu below:\n"
                   "(1-CK) create_keys\n"
                   "(2-CC) compute_checksum\n"
                   "(3-VC) verify_checksum\n"
                   "(4-EM) encrypt_message\n"
                   "(5-DM) decrypt_message\n"
                   "(6-BK) break_key\n "
                   "Please enter the option you want:\n")
    # Execute the chosen operation.
    if action in ['1', 'CK', 'ck', 'create_keys']:
        create_keys_interactive()
    elif action in ['2', 'CC', 'cc', 'compute_checksum']:
        compute_checksum_interactive()
    elif action in ['3', 'VC', 'vc', 'verify_checksum']:
        verify_checksum_interactive()
    elif action in ['4', 'EM', 'em', 'encrypt_message']:
        encrypt_message_interactive()
    elif action in ['5', 'DM', 'dm', 'decrypt_message']:
        decrypt_message_interactive()
    elif action in ['6', 'BK', 'bk', 'break_key']:
        break_key_interactive()
    else:
        print("Unknown action: '{0}'".format(action))


def create_keys_interactive():
    """
    Create new public keys

    :return: the private key (d, n) for use by other interactive methods
    """

    key_pair = create_keys()
    pub = get_public_key(key_pair)
    priv = get_private_key(key_pair)
    print("Public key: ")
    print(pub)
    print("Private key: ")
    print(priv)
    return priv


def compute_checksum_interactive():
    """
    Compute the checksum for a message, and encrypt it
    """

    priv = create_keys_interactive()

    message = input('Please enter the message to be checksummed: ')

    hash = compute_checksum(message)
    print('Hash:',as_hex(hash))
    cipher = apply_key(priv, hash)
    print('Encrypted Hash:', as_hex(cipher))


def verify_checksum_interactive():
    """
    Verify a message with its checksum, interactively
    """

    pub = enter_public_key_interactive()
    message = input('Please enter the message to be verified: ')
    recomputed_hash = compute_checksum(message)

    string_hash = input('Please enter the encrypted hash (in hexadecimal): ')
    encrypted_hash = int(string_hash, 16)
    decrypted_hash = apply_key(pub, encrypted_hash)
    print('Recomputed hash:', as_hex(format(recomputed_hash)))
    print('Decrypted hash: ', as_hex(format(decrypted_hash)))
    if recomputed_hash == decrypted_hash:
        print('Hashes match -- message is verified')
    else:
        print('Hashes do not match -- has tampering occured?')


def encrypt_message_interactive():
    """
    Encrypt a message
    """

    message = input('Please enter the message to be encrypted: ')
    pub = enter_public_key_interactive()
    encrypted = ''
    for c in message:
        ciphernumber = apply_key(pub,ord(c))
        encrypted += as_hex(ciphernumber)
    print("Encrypted message:", encrypted)


def decrypt_message_interactive(priv = None):
    """
    Decrypt a message
    """

    encrypted = input('Please enter the message to be decrypted: ')
    if priv is None:
        priv = enter_key_interactive('private')
    message = ''
    for i in range(0, len(encrypted), HEX_LENGTH):
        enc_string = encrypted[i:i + HEX_LENGTH]
        enc = int(enc_string, 16)
        dec = apply_key(priv, enc)
        if dec >= 0 and dec < 256:
            message += chr(dec)
        else:
            print('Warning: Could not decode encrypted entity: ' + enc_string)
            print('         decrypted as: ' + str(dec) + ' which is out of range.')
            print('         inserting _ at position of this character')
            message += '_'
    print("Decrypted message:", message)


def break_key_interactive():
    """
    Break key, interactively
    """

    pub = enter_public_key_interactive()
    priv = break_key(pub)
    print("Private key:")
    print(priv)
    decrypt_message_interactive(priv)


def enter_public_key_interactive():
    """
    Prompt user to enter the public modulus.

    :return: the tuple (e,n)
    """

    print('(Using public exponent = ' + str(PUBLIC_EXPONENT) + ')')
    string_modulus = input('Please enter the modulus (decimal): ')
    modulus = int(string_modulus)
    return (PUBLIC_EXPONENT, modulus)


def enter_key_interactive(key_type):
    """
    Prompt user to enter the exponent and modulus of a key

    :param key_type: either the string 'public' or 'private' -- used to prompt the user on how
                     this key is interpretted by the program.
    :return: the tuple (e,n)
    """
    string_exponent = input('Please enter the ' + key_type + ' exponent (decimal): ')
    exponent = int(string_exponent)
    string_modulus = input('Please enter the modulus (decimal): ')
    modulus = int(string_modulus)
    return (exponent, modulus)


def compute_checksum(string):
    """
    Compute simple hash

    Given a string, compute a simple hash as the sum of characters
    in the string.

    (If the sum goes over sixteen bits, the numbers should "wrap around"
    back into a sixteen bit number.  e.g. 0x3E6A7 should "wrap around" to
    0xE6A7)

    This checksum is similar to the internet checksum used in UDP and TCP
    packets, but it is a two's complement sum rather than a one's
    complement sum.

    :param str string: The string to hash
    :return: the checksum as an integer
    """

    total = 0
    for c in string:
        total += ord(c)
    total %= 0x8000  # Guarantees checksum is only 4 hex digits
    # How many bytes is that?
    #
    # Also guarantees that that the checksum will
    # always be less than the modulus.
    return total


# ---------------------------------------
# Do not modify code above this line
# ---------------------------------------

def create_keys():
    """
    Create the public and private keys.

    :return: the keys as a three-tuple: (e,d,n)
    """
    e = PUBLIC_EXPONENT
    tup_n_z = create_n_and_z()
    n = tup_n_z[0]
    d = create_d(e, tup_n_z[1])
    key_tup = (e, d, n)
    return key_tup


def create_p():
    """
    To generate the random prime number p
    using random module
    :return: p as bits
    """
    p = generate_prime_nums()
    print(p)
    p_totient = p - 1
    while p_totient % PUBLIC_EXPONENT == 0:
        p += 2
        if prime_checker(p):
            p_totient = p - 1
    else:
        p_totient = p_totient
    tup_p = (p, p_totient)
    print(p)
    return tup_p


def generate_prime_nums():
    """
    To generate random prime number
    :return: prime number
    """
    num = random.randint(MIN_PRIME, MAX_PRIME)
    while True:
        if prime_checker(num):
            break
        else:
            num = random.randint(MIN_PRIME, MAX_PRIME)
    return num


def create_q():
    """
    To generate the random prime number q
     using random
    :return: q as bits
    """
    q_totient = 0
    q = generate_prime_nums()
    while True:
        if prime_checker(q):
            q_totient = q - 1
            if q_totient % PUBLIC_EXPONENT != 0:
                break
            else:
                q += 2
        else:
            q = generate_prime_nums()
    tup_q = (q, q_totient)
    return tup_q


def prime_checker(num):
    """
    To check if the number is prime or not
    :return:
    """
    checker = True
    counter = 0
    if num > 1:
        if num % 2 != 0:
            for i in range(3, num + 1):
                if num % i == 0:
                    counter += 1
                    if num == i and counter == 1:
                        checker = True
                else:
                    checker = False
        else:
            checker = False
    return checker


def create_n_and_z():
    """
    To create the modulus number n
    by multiplying p and q
    :return: the n
    """
    tup_p = create_p()
    tup_q = create_q()
    n = 0
    z = 0
    while True:
        if tup_p[0] != tup_q[0]:
            n = tup_p[0]*tup_q[0]
            z = tup_p[1]*tup_q[1]
            break
        else:
            tup_q = create_q()
    tup_n_z = (n, z)
    print(f"The value of p is: {tup_p[0]}. The value of q is: {tup_q[0]}")
    return tup_n_z


def create_d(e, z):
    """
    To generate the private key d from The Euclid's Method (de%z == 1)
    :return: d
    """
    d = 0 #the d value
    new_d = 1
    r = z
    new_r = e
    var = 0
    while new_r != 0:
        var = r // new_r
        (d, new_d) = (new_d, d-var * new_d)
        (r, new_r) = (new_r, r - var * new_r)
    if r > 1:
        return "Not invertible"
    elif d < 0:
        d = d + z
    return d


def apply_key(key, m):
    """
    Apply the key, given as a tuple (e,n) or (d,n) to the message.

    This can be used both for encryption and decryption.

    :param tuple key: (e,n) or (d,n)
    :param int m: the message as a number 1 < m < n (roughly)
    :return: the message with the key applied. For example,
             if given the public key and a message, encrypts the message
             and returns the cipher-text.
    """
    var = (int(m)**key[0]) % key[1]
    print(var)
    return var


def encrypt_message(key, m):
    """
    To encrypt the message into cipher-text
    :param key: A tuple
    :param m: the message given
    :return: the cipher-text
    """
    cipher_text = (m**key[0]) % key[1]
    print(key[0], key[1])
    return cipher_text


def decrypt_message(key, m):
    decrypted_message = (m**key[0]) % key[1]
    return decrypted_message


def break_key(pub):
    """
    Break a key.  Given the public key, find the private key.
    Factorizes the modulus n to find the prime numbers p and q.

    You can follow the steps in the "optional" part of the in-class
    exercise.

    :param pub: a tuple containing the public key (e,n)
    :return: a tuple containing the private key (d,n)
    """
    tup_p_q = find_p_and_q(pub[1])
    z = find_z(tup_p_q)
    d = create_d(pub[0], z)
    tup_priv_key = (d, pub[1])
    return tup_priv_key


def find_z(tup_p_q):
    """
    To find z in break_key
    :param tup_p_q: the tuple consisting p and q
    :return:
    """
    p_totient = tup_p_q[0]-1
    q_totient = tup_p_q[1]-1
    z = p_totient*q_totient
    return z


def find_p_and_q(n):
    """
    To find the factors of n which is p and q
    :param n: the public modulus
    :return:
    """
    temp_list = []
    while n > 1:
        for i in range(2, n + 1):
            if n % i == 0:
                n /= i
                temp_list.append(i)
    tup_p_q = (temp_list[0], temp_list[1])
    return tup_p_q
# ---------------------------------------
# Do not modify code below this line
# ---------------------------------------


def get_public_key(key_pair):
    """
    Pulls the public key out of the tuple structure created by
    create_keys()

    :param key_pair: (e,d,n)
    :return: (e,n)
    """

    return (key_pair[0], key_pair[2])


def get_private_key(key_pair):
    """
    Pulls the private key out of the tuple structure created by
    create_keys()

    :param key_pair: (e,d,n)
    :return: (d,n)
    """

    return (key_pair[1], key_pair[2])


def as_hex(number):
    """
    Convert integer to a zero-padded hex string with the required number
    of characters to represent n, d, or and encrypted message.

    :param int number: to format
    :return: The formatted string
    """

    return "{:0{digits}x}".format(number,digits=str(HEX_LENGTH))

main()
