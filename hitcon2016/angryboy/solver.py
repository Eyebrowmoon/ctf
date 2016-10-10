#!/usr/bin/python

from Crypto.Cipher import AES

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-ord(s[-1])]

class AESCipher:
    def __init__( self, key ):
        """
        Requires hex encoded param as a key
        """
        self.key = key.decode("hex")

    def encrypt( self, raw ):
        """
        Returns hex encoded encrypted value!
        """

        raw = pad(raw)
        iv = "0011223344556677"
        cipher = AES.new( self.key, AES.MODE_CBC, iv )
        return ( iv + cipher.encrypt( raw ) ).encode("hex")

    def decrypt( self, enc ):
        """
        Requires hex encoded param to decrypt
        """
        enc = enc.decode("hex")

        iv = "0011223344556677"

        # iv = enc[:16]
        # enc= enc[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv )
        a = cipher.decrypt(enc)
        print a.encode("hex")
        print a
        print unpad(a)
        print 'sival'

        return unpad(a)

if __name__== "__main__":
    key = "43E39FEEC5698CFDB4DF4B8F851EAA45"

    ciphertext = "016264da521215abc24fd0d6bb2bd5e6986164b5bb3b2d1df750b2da6507a0e76734a92105582f1dee5f6e56f0144573"

    key=key[:32]

    decryptor = AESCipher(key)
    plaintext = decryptor.decrypt(ciphertext)

    print plaintext
    print "ohno"
