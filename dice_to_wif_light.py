#Program Input:

print "\n99 Dice Rolls to Private Key - Light Version:"
print "*widen terminal window and re-run program to fit the input guide on one line*\n"
print "Input Guide:               |---------------------------------------------------------------------------------------------------|"

dice_rolls = raw_input("Enter 99 Dice Rolls (1-6):  ")


# Imported Libraries:

import hashlib, binascii


# Base 58 Encoding:

base58_symbol_map = {

0 :'1',   10:'B',   20:'M',   30:'X',   40:'h',   50:'s',
1 :'2',   11:'C',   21:'N',   31:'Y',   41:'i',   51:'t',
2 :'3',   12:'D',   22:'P',   32:'Z',   42:'j',   52:'u',
3 :'4',   13:'E',   23:'Q',   33:'a',   43:'k',   53:'v',
4 :'5',   14:'F',   24:'R',   34:'b',   44:'m',   54:'w',
5 :'6',   15:'G',   25:'S',   35:'c',   45:'n',   55:'x',
6 :'7',   16:'H',   26:'T',   36:'d',   46:'o',   56:'y',
7 :'8',   17:'J',   27:'U',   37:'e',   47:'p',   56:'y',
8 :'9',   18:'K',   28:'V',   38:'f',   48:'q',   57:'z',
9 :'A',   19:'L',   29:'W',   39:'g',   49:'r'

}

def base10to58( number ):
	base58_string = ''
	current = number
	while current != 0:
		remainder = current % 58
		remainder_string = base58_symbol_map[remainder]
		base58_string = remainder_string + base58_string
		current = current / 58
	return base58_string


# Private Key Validity Check:

max_private_key = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def valid_key(private_key):
	return private_key <= max_private_key


# Private Key to Wallet Import Format (WIF) Conversion:

base6       = dice_rolls.replace('6','0')

base10      = int(str(base6),6)	

base16      = '{:064x}'.format(base10)

prehash     = '80' + base16

hash1       = hashlib.sha256( binascii.unhexlify( prehash ) ).hexdigest()

hash2       = hashlib.sha256( binascii.unhexlify( hash1   ) ).hexdigest()

checksum    = hash2[:8]

hex_wif     = prehash + checksum

base58_wif  = base10to58(int(hex_wif,16))


# Program Output:

print "Valid Private Key?:        "  , valid_key(base10), "\n"
print "Private Key (base  6):     "  , base6
print "Private Key (base 10):     "  , base10
print "Private Key (base 16):     "  , base16
print "Pre-Hash:                "    , prehash
print "Sha256 Hash #1:            "  , hash1
print "Sha256 Hash #2:            "  , hash2
print "Double Sha256 Checksum:    "  , checksum
print "WIF (base 16):           "    , hex_wif, "\n"
print "WIF (base 58):           "    , base58_wif, "\n"