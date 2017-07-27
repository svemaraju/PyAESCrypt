from Crypto.Cipher import AES
import base64
import hashlib

class PyAesCrypt(object):
    """
    Class for implementing AES encryption and decryption in python,
    compatible with the AESCrypt library in Android, Ruby and Objective-C
    """
    
    def __init__(self,encoding=True):
        
        # Use 16 byte empty initialization vector for compatibility.
        self.iv = bytes([0x00 for i in range(16)])
        self.encoding = encoding
    
    def encrypt(self,key,message):
        
        cipher = AES.new(self._hashkey(key=key),AES.MODE_CBC,self.iv)
        cipher_text = cipher.encrypt(self.pkcs7padding(data=message))
        
        if self.encoding:
            
            return base64.b64encode(s=cipher_text)
        
        return cipher_text
    
    def pkcs7padding(self,data):
        
        bs = 16
        padding = bs - len(data) % bs
        padding_text = chr(padding) * padding
        padded = data + padding_text
        return padded
    
    def pkcs7decode(self, text):

        if type(text) is bytes:
            pad = ord(text.decode("utf-8")[-1])
            return text[:-pad]
        else:
            raise RuntimeError("bytes required found %s" % type(text))
    
    def _hashkey(self,key):
        
        return hashlib.sha256(key.encode()).digest()
    
    def decrypt(self,key,message):
        
        cipher = AES.new(self._hashkey(key=key),AES.MODE_CBC,self.iv)
        
        if self.encoding:
            resp = cipher.decrypt(ciphertext=base64.b64decode(s=message))
        else:
            resp = cipher.decrypt(ciphertext=message)
        
        return self.pkcs7decode(text=resp)