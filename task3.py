
from Crypto.Util import number
from fractions import gcd
import random
 #e = 65537 = 2^16 +1


def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def multiplicative_inverse(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def getKey(p,q):
    n = p * q
    phi = (p-1) *(q-1)
    e = 65537 # set by lab requirement, the public key
    if(e > phi):
        print("Invalid primes. Retry")
        exit()
    g = gcd(e, phi)
    while g != 1:
        print("G not equal. Retry")
        # is it even possible?

    d= multiplicative_inverse(e, phi)

    return((e,n), (d,n)) # e is the public key, d is private key, n is modulus for both pubic and private key


#c = m^e %n where e is public key and n is common modular value
def encrypt(pubK, plaintext):
    key, n = pubK
    cipher = [(ord(char) ** key) % n for char in plaintext]
    return cipher


# m = c^
def decrypt(privK, cipherText):
    key, n = privK
    plain = [chr((char ** key) % n) for char in cipherText]
    return ''.join(plain)

def main():
    bitSize = random.randrange(8, 13) #don't change lower bound, could change upper bound to 2048
    print(bitSize)
    bitSize2 = random.randrange(8,13) # higher the upperbounds, longer the ciphertext and it takes to decrypt
    print(bitSize2)
    p = number.getPrime(bitSize)
    q = number.getPrime(bitSize2)
    public, private = getKey(p,q)
    print(public) # public key is always 65537
    print(private)
    message = input("Enter the message to encrypt  ")
    encrypted_msg = encrypt(public, message) #public key cryptograpgy, encrypt with public key
    print ("Your encrypted message is: ")
    print (''.join(map(lambda x: str(x), encrypted_msg)))
    print ("Decrypting message with public key")
    print ("Your message is:")
    decryptedMsg= decrypt(private, encrypted_msg)
    print (decryptedMsg)

if __name__ == "__main__":
    main()