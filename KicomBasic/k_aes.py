from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

######################
# AES Crypto Example #
######################

key = b'1234567890123456'
data = b'aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbcccccccccccccccc'

# enc
encCipher = AES.new(key, AES.MODE_CBC)
iv = encCipher.iv
ciphertext = encCipher.encrypt(pad(data, AES.block_size))
print("etext:",ciphertext)

# dec
decCipher = AES.new(key, AES.MODE_CBC,iv=iv)
ptext = unpad(decCipher.decrypt(ciphertext), AES.block_size)


print("ptext:", ptext)
print("eiv:", encCipher.iv)
print("div:", decCipher.iv)