
#implementation of Diffie Hellman Key Exchange 

# task 2a
	#changing 

from padding import *
from Crypto.Cipher import AES
import hashlib
import os
'''
are we assumed that decryption uses same IV that was used for encryption?
A = g^a % p
B = g^b %p 
think of a and b as the private key for Alice and Bob respectively
'''
def DHKExchange(a, b):
	p = 37 # must be prime 
	g = 5 # must be prime 

	a = int(a)
	b = int(b)

	A = pow(g, a, p) # Alice
	B = pow(g, b, p) # Bob

	# part 2a Mallory modifies 
	A = p 
	B = p 

	stringA = str(pow(B, a, p)) # would equal to 0 
	stringB = str(pow(A, b, p)) # would equal to 0 
	print(stringA)
	# key is essentially sha256(0) 
	kA = hashlib.sha256(stringA.encode('ascii')).hexdigest() # in hex
	kB = hashlib.sha256(stringB.encode('ascii')).hexdigest() # kA = kB
	

	#turn to byteString
	m0 = "Hi Bob!".encode('ascii') # pkcs7 padding is 16 -len(m0) = 9 -> chr(9) 
	m1 = "Hi Alice!".encode('ascii')

	#padding to 128 bits, mult of 16
	m0 = pad(m0, 16, style= 'pkcs7')
	m1 = pad(m1, 16, style= 'pkcs7')
	
	key = kA[0:32] # key is 32*4 = 128bit= 16 byte
	#print(len(key.encode('utf-8'))) #test to see if key is 32 byte. utf-8 encode to bytes
	
	iv = os.urandom(16) # urandom of 16 bytes = 128bit
	cipher = AES.new(key, AES.MODE_CBC, iv )

	''''
	part2a) if Alice and Bob's key is 0 and the cipherText is given. Mallory/Adversary can create 
		AES decipher with the known key (valued 0 ), the mode CBC if given and any randomly generated iv
		to reverse engineer/find the original plaintext.
	
	Findings: if you use random iv2, you'll get Bob's String
			  if you use same iv used for encryption, both string are found 
	'''
	cipherTextM0 = cipher.encrypt(m0)
	cipherTextM1 = cipher.encrypt(m1)
	
	#random iv2 doesn't produce exact result for decryptedM0
	#iv2 = os.urandom(16)

	decipher = AES.new(key, AES.MODE_CBC, iv)

	decryptedTextM0 = decipher.decrypt(cipherTextM0)
	decryptedTextM1 = decipher.decrypt(cipherTextM1)
	print(decryptedTextM0)
	print(decryptedTextM1)


	#print(cipher.decrypt(cipherTextM1))

	

def main():
	a = input("Enter the power exponent/private key a for Alice: ")
	b = input("Enter the power exponent/private key b for Bob: ")
	DHKExchange(a,b)

if __name__ == "__main__":
	main()