
#implementation of Diffie Hellman Key Exchange 

from padding import *
from Crypto.Cipher import AES
import hashlib
import os

def DHKExchange(a, b):

	# part a
	#p = 37 # must be prime 
	#g = 5 # must be prime 

	# part b 
	p = int("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D109838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371", 16)
	g = int("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5", 16)

	a = int(a)
	b = int(b)

	A = pow(g, a, p) # Alice
	B = pow(g, b, p) # Bob

	stringA = str(pow(B, a, p))
	stringB = str(pow(A, b, p))

	kA = hashlib.sha256(stringA.encode('ascii')).hexdigest() # in hex
	kB = hashlib.sha256(stringB.encode('ascii')).hexdigest() # kA = kB
	

	m0 = "Hi Bob!".encode('ascii') # pkcs7 padding is 16 -len(m0) = 9 -> chr(9) 
	m1 = "Hi Alice!".encode('ascii')
	#print(m0)
	#print(m1)
	m0 = pad(m0, 16, style= 'pkcs7')
	m1 = pad(m1, 16, style= 'pkcs7')
	#print(m0)
	#print(m1)
	key = kA[0:32] # key is 32*4 = 128bit long
	#print(len(key.encode('utf-8'))) #test to see if key is 32 byte. utf-8 encode to bytes
	
	iv = os.urandom(16) # urandom of 16 bytes = 128
	cipher = AES.new(key, AES.MODE_CBC, iv )

	cipherTextM0 = cipher.encrypt(m0)
	#print(cipherTextM0)	
	cipherTextM1 = cipher.encrypt(m1)
	#print(cipherTextM1)

def main():
	a = input("Enter the power exponent a for Alice: ") # their private key
	b = input("Enter the power exponent b for Bob: ")	# their private key
	DHKExchange(a,b)

if __name__ == "__main__":
	main()