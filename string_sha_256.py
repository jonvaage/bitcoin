# Program Input:

input_string = '945450ba1e8715b0475375f396573b5c28776dff24a41b07d4ed82b549a8d6df'


# Initial Hash Values - fractional part of the square roots of the first 8 primes:

def fsr(prime):
	return int((( prime**(1/2.0)) - int( prime**(1/2.0))) * 2**32 )

A = fsr( 2)   # 0x6a09e667
B = fsr( 3)   # 0xbb67ae85
C = fsr( 5)   # 0x3c6ef372
D = fsr( 7)   # 0xa54ff53a
E = fsr(11)   # 0x510e527f
F = fsr(13)   # 0x9b05688c
G = fsr(17)   # 0x1f83d9ab
H = fsr(19)   # 0x5be0cd19

hash_values = [A,B,C,D,E,F,G,H]


# Round Constants - fractional part of the cube roots of the first 64 primes:

def fcr(prime):
	return int((( prime**(1/3.0)) - int( prime**(1/3.0))) * 2**32 )

K = [

fcr(  2), fcr(  3), fcr(  5), fcr(  7),   # 0x428a2f98  0x71374491  0xb5c0fbcf  0xe9b5dba5
fcr( 11), fcr( 13), fcr( 17), fcr( 19),   # 0x3956c25b  0x59f111f1  0x923f82a4  0xab1c5ed5
fcr( 23), fcr( 29), fcr( 31), fcr( 37),   # 0xd807aa98  0x12835b01  0x243185be  0x550c7dc3
fcr( 41), fcr( 43), fcr( 47), fcr( 53),   # 0x72be5d74  0x80deb1fe  0x9bdc06a7  0xc19bf174
fcr( 59), fcr( 61), fcr( 67), fcr( 71),   # 0xe49b69c1  0xefbe4786  0x0fc19dc6  0x240ca1cc
fcr( 73), fcr( 79), fcr( 83), fcr( 89),   # 0x2de92c6f  0x4a7484aa  0x5cb0a9dc  0x76f988da
fcr( 97), fcr(101), fcr(103), fcr(107),   # 0x983e5152  0xa831c66d  0xb00327c8  0xbf597fc7
fcr(109), fcr(113), fcr(127), fcr(131),   # 0xc6e00bf3  0xd5a79147  0x06ca6351  0x14292967
fcr(137), fcr(139), fcr(149), fcr(151),   # 0x27b70a85  0x2e1b2138  0x4d2c6dfc  0x53380d13
fcr(157), fcr(163), fcr(167), fcr(173),   # 0x650a7354  0x766a0abb  0x81c2c92e  0x92722c85
fcr(179), fcr(181), fcr(191), fcr(193),   # 0xa2bfe8a1  0xa81a664b  0xc24b8b70  0xc76c51a3
fcr(197), fcr(199), fcr(211), fcr(223),   # 0xd192e819  0xd6990624  0xf40e3585  0x106aa070
fcr(227), fcr(229), fcr(233), fcr(239),   # 0x19a4c116  0x1e376c08  0x2748774c  0x34b0bcb5
fcr(241), fcr(251), fcr(257), fcr(263),   # 0x391c0cb3  0x4ed8aa4a  0x5b9cca4f  0x682e6ff3
fcr(269), fcr(271), fcr(277), fcr(281),   # 0x748f82ee  0x78a5636f  0x84c87814  0x8cc70208
fcr(283), fcr(293), fcr(307), fcr(311)    # 0x90befffa  0xa4506ceb  0xbef9a3f7  0xc67178f2
	
]


# Hashing Functions:

def rotate( number, u ):
	bits = '{:032b}'.format( number )
	front_bits = bits[ (32-u) : (  32) ]
	back_bits  = bits[ (   0) : (32-u) ]
	return int( (front_bits + back_bits), 2)

def sigma_0( number ):
	x = rotate( number,  7 )
	y = rotate( number, 18 )
	z = number >> 3
	return x ^ y ^ z

def sigma_1( number ):
	x = rotate( number, 17 )
	y = rotate( number, 19 )
	z = number >> 10
	return x ^ y ^ z

def SIGMA_0( number ):
	x = rotate( number,  2 )
	y = rotate( number, 13 )
	z = rotate( number, 22 )
	return x ^ y ^ z

def SIGMA_1( number ):
	x = rotate( number,  6 )
	y = rotate( number, 11 )
	z = rotate( number, 25 )
	return x ^ y ^ z

def choose( u, v, w ):
	return (u & v) ^ ((~u) & w)

def majority( u, v, w ):
	return (u & v) ^ (u & w) ^ (v & w)


# Prepare Binary:

binary_string 	= ''.join( '{:08b}'.format( ord(x)) for x in input_string )

binary_length  	=  '{:064b}'.format( len(binary_string) )

padding = 0
while (len(binary_string) + 1 + padding + 64) % 512 != 0 :
	padding += 1

preped_binary	= binary_string + '1' + ''.zfill(padding) + binary_length

split_binary 	= [preped_binary[i:i+512] for i in range(0, len(preped_binary), 512)]


# Message Block Processing:

for block in split_binary[:]:


	# 64 Message Inputs (W): 
	
	W = [''.zfill(32)] * 64
	block_slices = [block[i:i+32] for i in range(0, 512, 32)]

	for i in range( 0, 16):
		W[i] = int( block_slices[i], 2)
	for i in range(16, 64):
		W[i] = ( sigma_1( W[i-2] ) + W[i-7] + sigma_0( W[i-15] ) + W[i-16] ) % 2**32


	# Initialize Round Variables:

	a = hash_values[0]
	b = hash_values[1]
	c = hash_values[2]
	d = hash_values[3]
	e = hash_values[4]
	f = hash_values[5]
	g = hash_values[6]
	h = hash_values[7]


	# Compression Function Main Loop:

	for i in range( 0, 64):

		temp1 = ( h + SIGMA_1(e) + choose(e,f,g) + K[i] + W[i] ) % 2**32

		temp2 = ( SIGMA_0(a) + majority(a,b,c) ) % 2**32

		h = g
		g = f
		f = e
		e = ( d + temp1 ) % 2**32
		d = c
		c = b
		b = a
		a = ( temp1 + temp2 ) % 2**32


	# Combine Block Hash Values with Compressed Variables:

	block_values = [a,b,c,d,e,f,g,h]

	hash_values = [ (hash_values[i] + block_values[i]) % 2**32 for i in range(0,8) ]


# Produce Final Hash Digest:

hex_list = [ '{:08x}'.format( value ) for value in hash_values ]

digest = ''.join( hex_list)

print digest