##### Program Input #####

print
print "Bitcoin Key Pair and Address from Dice Rolls:"
print " *If the input guide doesn't fit in one line," \
        " widen the window and press enter.*"

dice_rolls = ""


# Input Verification:

while dice_rolls == "":
    print
    print "Input Guide:" + " " * 15 + "|" + "-" * 99 + "|"
    dice_rolls = raw_input("Enter 99 Dice Rolls (1-6):  ")
    for char in dice_rolls:
        if char not in '123456':
            print " *Error: Only characters 1-6. Try again:"
            dice_rolls = ""; break
    if  dice_rolls == "": continue
    if len( dice_rolls ) > 99:
        print " *Error: Too many characters. Try again:"
        dice_rolls = ""; continue
    if int( dice_rolls.replace( '6', '0' ), 6 ) == 0:
        print " *Error: Zero is an invalid private key. Try again:"
        dice_rolls = ""




##### Elliptic Curve Cryptography #####


# secp256k1 Curve Parameters: [ y^2=x^3+7 mod p ]


# Prime Modulus: [ 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 -1 ]

prime  = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f


# Origin Point Coordinates:

Gx     = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798

Gy     = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8

origin = ( Gx, Gy )


# Points within the Finite Field that are Scalar Multiples of the Origin:

order  = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141


# Modular Inverse: Fermat's Little Theorem [ a^-1 mod p = a^(p-2) mod p ]

def mod_inv( number ):
    return pow( number, prime-2, prime )


# Elliptic Curve Point Addition:

def EC_add( P, Q ):
    Px, Py = P[0], P[1]
    Qx, Qy = Q[0], Q[1]
    slope  = ( (Py - Qy) * mod_inv( Px - Qx ) ) % prime
    Rx     = ( slope**2 - Px - Qx ) % prime
    Ry     = ( slope * (Px - Rx) - Py ) % prime
    return   ( Rx, Ry )


# Elliptic Curve Point Doubling:

def EC_double( P ):
    Px, Py = P[0], P[1]
    slope  = ( 3 * Px**2 ) * mod_inv( 2 * Py )% prime
    Rx     = ( slope**2 - Px - Px ) % prime
    Ry     = ( slope * (Px - Rx) - Py ) % prime
    return   ( Rx, Ry )


# Elliptic Curve Point Multiplication:

def EC_multiply( P, number ):
    if number == 0 or number >= order: raise Exception("Invalid Private Key")
    binary = '{:b}'.format(number)[1:]
    R = P
    for bit in binary:
        R = EC_double( R )
        if bit == '1':
            R = EC_add( R, P )
    return R




##### Hashing Functions #####


def sha256( message_hex ):


    # Initial Hash Words: fractional part of the square roots of the 1st 8 primes:

    A = 0x6a09e667
    B = 0xbb67ae85
    C = 0x3c6ef372
    D = 0xa54ff53a
    E = 0x510e527f
    F = 0x9b05688c
    G = 0x1f83d9ab
    H = 0x5be0cd19


    # Round Constants: fractional part of the cube roots of the 1st 64 primes:

    K = [ 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
          0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
          0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
          0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
          0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
          0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
          0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
          0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
          0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
          0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
          0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
          0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
          0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
          0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
          0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
          0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2  ]


    # Message Padding:

    def padding_length( message ):
            padding = 0
            while ( len( message ) + 1 + padding + 64 ) % 512 != 0: padding += 1
            return padding


    # Message Preparation:

    message_bin = '{:0{}b}'.format( int( message_hex, 16 ), len( message_hex ) * 4 )

    padding_bin = '1' + '{:0{}b}'.format( 0, padding_length( message_bin ))

    padding_hex = '{:0{}x}'.format( int( padding_bin, 2), len( padding_bin ) / 4 )

    padded_hex  = message_hex + padding_hex

    length_hex  = '{:016x}'.format( len( message_bin ))

    preped_hex  = padded_hex + length_hex

    split_hex   = [ preped_hex[i:i+128] for i in range( 0, len( preped_hex), 128)]


    # Enforce 32-Bit Integers:

    def u32( number ):
           return number % 2**32


    # Rotate Right:

    def rotate_right( number, x ):
        bits       = '{:032b}'.format( number )
        front_bits = bits[ 32-x : 32   ]
        back_bits  = bits[  0   : 32-x ]
        return       int( ( front_bits + back_bits ), 2 )


    # Transformation Functions:

    def sigma_0( number ):
        x = rotate_right( number,  7 )
        y = rotate_right( number, 18 )
        z = number >> 3
        return x ^ y ^ z

    def sigma_1( number ):
        x = rotate_right( number, 17 )
        y = rotate_right( number, 19 )
        z = number >> 10
        return x ^ y ^ z

    def SIGMA_0( number ):
        x = rotate_right( number,  2 )
        y = rotate_right( number, 13 )
        z = rotate_right( number, 22 )
        return x ^ y ^ z

    def SIGMA_1( number ):
        x = rotate_right( number,  6 )
        y = rotate_right( number, 11 )
        z = rotate_right( number, 25 )
        return x ^ y ^ z

    def choose( x, y, z ):
        return (x & y) ^ ((~x) & z)

    def majority( x, y, z ):
        return (x & y) ^ (x & z) ^ (y & z)


    # Message Block Processing:

    for block in split_hex:


        # Hash Word Input:

        a = A;    b = B;    c = C;    d = D;    e = E;    f = F;    g = G;    h = H


        # 64 Message Words: 

        X = [0] * 64

        for i in range( 0, 16):
            X[i] = int( block[ i*8 : (i+1)*8 ], 16)

        for i in range(16, 64):
            X[i] = u32( sigma_1( X[i-2] ) + X[i-7] + sigma_0( X[i-15] ) + X[i-16] )


        # Compression Function Main Loop:

        for i in range( 0, 64):

            t1 = u32( h + SIGMA_1(e) + choose( e, f, g ) + K[i] + X[i] )
            t2 = u32( SIGMA_0(a) + majority( a, b, c ) )

            h  = g
            g  = f
            f  = e
            e  = u32( d + t1 )
            d  = c
            c  = b
            b  = a
            a  = u32( t1 + t2 )


        # Hash Word Output:

        A = u32( A + a )
        B = u32( B + b )
        C = u32( C + c )
        D = u32( D + d )
        E = u32( E + e )
        F = u32( F + f )
        G = u32( G + g )
        H = u32( H + h )


    # Final Hash Digest:

    digest = ''.join( map( '{:08x}'.format, [ A, B, C, D, E, F, G, H ] ))

    return digest




##### RIPEMD-160 Code #####

def ripemd160( message_hex ):


    # Initial Hash Words in Little-Endian Form:

    A = 0x67452301    # 0x01234567 (big-endian form)
    B = 0xefcdab89    # 0x89abcdef (big-endian form)
    C = 0x98badcfe    # 0xfedcba98 (big-endian form)
    D = 0x10325476    # 0x76543210 (big-endian form)
    E = 0xc3d2e1f0    # 0xf0e1d2c3 (big-endian form)


    # Left Round Constants: zero & the square roots of the first 4 primes * 2^30

    KL = [ 0x00000000,      # 0
           0x5a827999,      # 2^(1/2) * 2^30
           0x6ed9eba1,      # 3^(1/2) * 2^30
           0x8f1bbcdc,      # 5^(1/2) * 2^30
           0xa953fd4e  ]    # 7^(1/2) * 2^30


    # Right Round Constants: the cube roots of the first 4 primes * 2^30 & zero

    KR = [ 0x50a28be6,      # 2^(1/3) * 2^30
           0x5c4dd124,      # 3^(1/3) * 2^30
           0x6d703ef3,      # 5^(1/3) * 2^30
           0x7a6d76e9,      # 7^(1/3) * 2^30
           0x00000000  ]    # 0


    # Message Word Order:

    RL = [ [  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 ] ,
           [  7,  4, 13,  1, 10,  6, 15,  3, 12,  0,  9,  5,  2, 14, 11,  8 ] ,
           [  3, 10, 14,  4,  9, 15,  8,  1,  2,  7,  0,  6, 13, 11,  5, 12 ] ,
           [  1,  9, 11, 10,  0,  8, 12,  4, 13,  3,  7, 15, 14,  5,  6,  2 ] ,
           [  4,  0,  5,  9,  7, 12,  2, 10, 14,  1,  3,  8, 11,  6, 15, 13 ] ]

    RR = [ [  5, 14,  7,  0,  9,  2, 11,  4, 13,  6, 15,  8,  1, 10,  3, 12 ] ,
           [  6, 11,  3,  7,  0, 13,  5, 10, 14, 15,  8, 12,  4,  9,  1,  2 ] ,
           [ 15,  5,  1,  3,  7, 14,  6,  9, 11,  8, 12,  2, 10,  0,  4, 13 ] ,
           [  8,  6,  4,  1,  3, 11, 15,  0,  5, 12,  2, 13,  9,  7, 10, 14 ] ,
           [ 12, 15, 10,  4,  1,  5,  8,  7,  6,  2, 13, 14,  0,  3,  9, 11 ] ]  


    # Message Word Shifts:

    SL = [ [  11, 14, 15, 12,  5,  8,  7,  9, 11, 13, 14, 15,  6,  7,  9,  8 ] ,
           [   7,  6,  8, 13, 11,  9,  7, 15,  7, 12, 15,  9, 11,  7, 13, 12 ] ,
           [  11, 13,  6,  7, 14,  9, 13, 15, 14,  8, 13,  6,  5, 12,  7,  5 ] ,
           [  11, 12, 14, 15, 14, 15,  9,  8,  9, 14,  5,  6,  8,  6,  5, 12 ] ,
           [   9, 15,  5, 11,  6,  8, 13, 12,  5, 12, 13, 14, 11,  8,  5,  6 ] ]

    SR = [ [   8,  9,  9, 11, 13, 15, 15,  5,  7,  7,  8, 11, 14, 14, 12,  6 ] ,
           [   9, 13, 15,  7, 12,  8,  9, 11,  7,  7, 12,  7,  6, 15, 13, 11 ] ,
           [   9,  7, 15, 11,  8,  6,  6, 14, 12, 13,  5, 14, 13, 13,  7,  5 ] ,
           [  15,  5,  8, 11, 14, 14,  6, 14,  6,  9, 12,  9, 12,  5, 15,  8 ] ,
           [   8,  5, 12,  9, 12,  5, 14,  6,  8, 13,  6,  5, 15, 13, 11, 11 ] ]


    # Little-Endian Word Formatting:

    def little_endian( hex_str ):
        W = [ hex_str[i:i+8] for i in range( 0, len( hex_str ), 8 ) ]
        for j in range( 0, len( W )):
            W[j] = W[j][6:] + W[j][4:6] + W[j][2:4] + W[j][:2]
        return ''.join( W )


    # Message Padding:

    def padding_length( message ):
        x = 0
        while ( len( message ) + 1 + x + 64 ) % 512 != 0: x += 1
        return x   


    # Message Preparation:

    message_bin = '{:0{}b}'.format( int( message_hex, 16 ), len( message_hex ) * 4 )

    padding_bin = '1' + '{:0{}b}'.format( 0, padding_length( message_bin ))

    padding_hex = '{:0{}x}'.format( int( padding_bin, 2), len( padding_bin ) / 4 )

    padded_hex  = message_hex + padding_hex

    length_hex  = '{:016x}'.format( len( message_bin ))

    preped_hex  = little_endian( padded_hex ) + length_hex[8:] + length_hex[:8]

    split_hex   = [ preped_hex[i:i+128] for i in range( 0, len( preped_hex ), 128) ]


    # 32-Bit Integer Enforcement:

    def u32( number ):
        return number % 2**32


    # Rotate Left:

    def rotate_left( number, x ):
        bits       = '{:032b}'.format( number )
        front_bits = bits[ x : 32 ]
        back_bits  = bits[ 0 :  x ]
        return       int( (front_bits + back_bits), 2)


    # Transformation Functions by Round:

    def T( hash_round, x, y, z ):  
        if hash_round == 0: return (x ^ y ^ z)
        if hash_round == 1: return (x & y) | (~x & z)
        if hash_round == 2: return (x | ~y) ^ z
        if hash_round == 3: return (x & z) | (y & ~z)
        if hash_round == 4: return (x ^ (y | ~z))


    # Message Block Processing:

    for block in split_hex:


        # Hash Word Input:

        aL = aR = A;    bL = bR = B;    cL = cR = C;    dL = dR = D;    eL = eR = E


        # 16 Message Words in Little-Endian Form: 

        X = [0] * 16

        for i in range( 0, 16):
            X[i] = int( block[ i*8 : (i+1)*8 ], 16)


        # Compression Function Left Loop:

        for i in range( 0, 5):
            for j in range( 0, 16):
                t1 = u32( aL + T( i, bL, cL, dL ) + X[ RL[i][j] ] + KL[i] )
                t2 = u32( rotate_left( t1, SL[i][j] ) + eL )
                aL = eL
                eL = dL
                dL = rotate_left( cL, 10)
                cL = bL
                bL = t2


        # Compression Function Right Loop:

        for i in range( 0, 5):
            for j in range( 0, 16):
                t3 = u32( aR + T( 4-i, bR, cR, dR ) + X[ RR[i][j] ] + KR[i] )
                t4 = u32( rotate_left( t3, SR[i][j] ) + eR )
                aR = eR
                eR = dR
                dR = rotate_left( cR, 10)
                cR = bR
                bR = t4


        # Hash Word Output:

        t5 = u32( B + cL + dR )
        B  = u32( C + dL + eR )
        C  = u32( D + eL + aR ) 
        D  = u32( E + aL + bR )
        E  = u32( A + bL + cR )
        A  = t5


    # Final Hash Digest:

    digest = little_endian( ''.join( map( '{:08x}'.format, [ A, B, C, D, E ] )))

    return digest




##### Formatting #####


# Base 58 Encoding:

base58_map = {  0 :'1',   10:'B',   20:'M',   30:'X',   40:'h',   50:'s',
                1 :'2',   11:'C',   21:'N',   31:'Y',   41:'i',   51:'t',
                2 :'3',   12:'D',   22:'P',   32:'Z',   42:'j',   52:'u',
                3 :'4',   13:'E',   23:'Q',   33:'a',   43:'k',   53:'v',
                4 :'5',   14:'F',   24:'R',   34:'b',   44:'m',   54:'w',
                5 :'6',   15:'G',   25:'S',   35:'c',   45:'n',   55:'x',
                6 :'7',   16:'H',   26:'T',   36:'d',   46:'o',   56:'y',
                7 :'8',   17:'J',   27:'U',   37:'e',   47:'p',   56:'y',
                8 :'9',   18:'K',   28:'V',   38:'f',   48:'q',   57:'z',
                9 :'A',   19:'L',   29:'W',   39:'g',   49:'r'             }


def base58( hex_string ):
    temp = hex_string
    base58_zeros = ''
    while temp[:2] == "00":
        base58_zeros = '1' + base58_zeros
        temp = temp[2:]
    number = int( hex_string, 16 )
    base58_string = ''
    while number != 0:
        remainder     = base58_map[ number % 58 ]
        base58_string = remainder + base58_string
        number        = number / 58
    return base58_zeros + base58_string




##### Private Key to Bitcoin Address #####


private_key       = int( dice_rolls.replace( '6', '0' ), 6 ) % order

public_key        = EC_multiply( origin, private_key )


# Private Key Wallet Import Format (WIF) Conversion:

privkey_hex       = '{:064x}'.format( private_key )

privkey_checksum  = sha256( sha256( '80' + privkey_hex ) )[:8]

wif_hex           = '80' + privkey_hex + privkey_checksum

wif_58            = base58( wif_hex )


# Bitcoin Address Generation (Uncompressed):

u_pubkey_hex      = '04' + '{:064x}{:064x}'.format( public_key[0], public_key[1] )

u_pubkey_hash     = '00' + ripemd160( sha256( u_pubkey_hex ))

u_pubkey_checksum = sha256( sha256( u_pubkey_hash ))[:8]

u_address_hex     = u_pubkey_hash + u_pubkey_checksum[:8]

u_address_58      = base58( u_address_hex )


# Bitcoin Address Generation (Compressed):

c_pubkey_prefix   = '02' if public_key[1] % 2 == 0 else '03'

c_pubkey_hex      = c_pubkey_prefix + '{:064x}'.format( public_key[0] )

c_pubkey_hash     = '00' + ripemd160( sha256( c_pubkey_hex ))

c_pubkey_checksum = sha256( sha256( c_pubkey_hash ))[:8]

c_address_hex     = c_pubkey_hash + c_pubkey_checksum[:8]

c_address_58      = base58( c_address_hex )




##### Program Output #####


print "  ( 6 -> 0 )"
print "Private Key (base  6):     " , dice_rolls.replace( '6', '0' )
print "Private Key (base 10):     " , private_key
print "Private Key (base 16):     " , privkey_hex
print
print "Wallet Import Format:      "
print "  Prefix + Privkey:      "   , '80' + privkey_hex
print "  SHA-256:                 " , sha256( '80' + privkey_hex )
print "  SHA-256 Again:           " , sha256( sha256( '80' + privkey_hex ) )
print "  Privkey Checksum:        " , privkey_checksum
print "  PrivKey (WIF base 16): "   , wif_hex
print "  PrivKey (WIF base 58): "   , wif_58
print
print "Public Key:"
print "  X Coordinate:            " , '{:064x}'.format( public_key[0] )
print "  Y Coordinate:            " , '{:064x}'.format( public_key[1] )
print "  Y Parity:                " , "Even" if public_key[1] % 2 == 0 else "Odd"
print
print "Bitcoin Address (Uncompressed):"
print "  Prefix + Pubkey X & Y: "   , u_pubkey_hex[:66] + "..."
print "                           " , u_pubkey_hex[66:]
print "  SHA-256:                 " , sha256( u_pubkey_hex )
print "  RIPEMD-160:              " , ripemd160( sha256( u_pubkey_hex ))
print "  PubKey Hash w/ Prefix: "   , u_pubkey_hash
print "  SHA-256:                 " , sha256( u_pubkey_hash )
print "  SHA-256 Again:           " , sha256( sha256( u_pubkey_hash ))
print "  4-Byte Checksum:         " , u_pubkey_checksum
print "  BTC Address (base 16): "   , u_address_hex
print "  BTC Address (base 58): "   , u_address_58
print
print "Bitcoin Address (Compressed):"
print "  Prefix + Pubkey X:     "   , c_pubkey_hex
print "  SHA-256:                 " , sha256( c_pubkey_hex )
print "  RIPEMD-160:              " , ripemd160( sha256( c_pubkey_hex ))
print "  PubKey Hash w/ Prefix: "   , c_pubkey_hash
print "  SHA-256:                 " , sha256( c_pubkey_hash )
print "  SHA-256 Again:           " , sha256( sha256( c_pubkey_hash ))
print "  4-Byte Checksum:         " , c_pubkey_checksum
print "  BTC Address (base 16): "   , c_address_hex
print "  BTC Address (base 58): "   , c_address_58
print