
#implementation of Diffie Hellman Key Exchange 


from padding import *
from Crypto.Cipher import AES
import hashlib
import os

'''
 A = g^a % p
'''
def DHKExchange(a, b):
	p = 37 # must be prime 
	'''

	part2b, g is modifed to 1, p and p-1
	if g = 1, kA and kB = 1 -> key = 1
	if g= p, kA and kB = 0 -> key = 0
	if A = p, kA and kB = 0 -> key = 0
	if g = p-1 for pow(g,a,p):
		if(a= odd):
			A = g
		if(a = even):
			A= 1
	'''
	g =  36 # must be prime 

	a = int(a)
	b = int(b)

	A = pow(g, a, p) # Alice
	B = pow(g, b, p) # Bob

	stringA = str(pow(B, a, p))  
	stringB = str(pow(A, b, p))  
	print(stringA)
	print(stringB)
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