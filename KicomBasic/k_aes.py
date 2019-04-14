from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

######################
# AES Crypto Example #
######################



class k_aes():
    """
    Enc/Decrypt Data using AES
    Args:
    key >= 16 bytes
    
    dec function need iv


    Example:
        #a = k_aes(b'0123456789012345')
        #plain = b'aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbcccccccccccccccc'

        #enc=a.enc(plain)
        #print(enc[1])
        #dec=a.dec(enc[0],enc[1])
        #print(dec)
    
    """
    def __init__(self, key):
        self.key = key
        
        pass

    def enc(self, data):
        self.aes = AES.new(self.key, AES.MODE_CBC)
        c_text = self.aes.encrypt(pad(data, AES.block_size))

        return c_text, self.aes.iv

    def dec(self, data, iv):
        self.aes = AES.new(self.key, AES.MODE_CBC, iv)
        p_text = unpad(self.aes.decrypt(data), AES.block_size)

        return p_text
    
