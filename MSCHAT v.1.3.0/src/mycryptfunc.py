import hashlib
import secrets
from binascii import hexlify

import base64
from cryptography.fernet import Fernet

def myencrypt(message: str, key: bytes) -> str:
    message = bytes(message.encode('utf-8'))
    return str(Fernet(key).encrypt(message).decode('utf-8'))

def mydecrypt(token: str, key: bytes) -> str:
    token = bytes(token.encode('utf-8'))
    return str(Fernet(key).decrypt(token).decode('utf-8'))

class DiffieHellman(object):
 
    # The following is the prime safe enough 
    # 6,144 bits introduced in RFC3526 (Might take some time to calculate DH)
    # predefined_p = 2^6144 - 2^6080 - 1 + 2^64 * { [2^6014 pi] + 929484 }
    # More values available in https://www.ietf.org/rfc/rfc3526.txt
    predefined_p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF
    predefined_g = 2
    
    # p, g, and publicKey should be open to the other party
    def __init__(self, p = None, g = None, privateKey = None, publicKey = None):
        if p is None or g is None:
            self.p = self.predefined_p
            self.g = self.predefined_g
        else:
            self.p = p
            self.g = g
        if privateKey is None or publicKey is None :
            self.privateKey = self.generatePriKey()
            self.publicKey = self.generatePubKey()
        else:
            self.privateKey = privateKey
            self.publicKey = publicKey
 
    def generatePriKey(self):
        return 2 + secrets.randbelow(self.p-1 -2 +1) # +1 because range exclude second parameter, unlike randint
        #return randint(2, self.p - 1) 
 
    def generatePubKey(self):
        return pow(self.g, self.privateKey, self.p)
 
    def generateKey(self, anotherKey):
        self.sharedSecret = pow(anotherKey, self. privateKey, self.p)
        s = hashlib.sha256(bytes(str(self.sharedSecret).encode('utf-8')))
        self.key = bytes(s.hexdigest().encode('utf-8'))
 
    def getKey(self):
        return hexlify(self.key)
        
    def getKeySize(self):
        return len(self.key) * 8
 
    def showDHKeyExchange(self):
        print ("Prime (p): ", self.p)
        print ("Generator (g): ", self.g)
        print ("Private key: ", self.privateKey)
        print ("Public key: ", self.publicKey)
        print ("Shared secret: ", self.sharedSecret)
        print ("Shared key: ", self.getKey())
        print ("Size of the key (bits):", self.getKeySize())
