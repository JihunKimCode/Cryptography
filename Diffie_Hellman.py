import random
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

#Fast Modular Exponentiation
def FME(g, a, p):
    product = 1
    g = g%p
    for i in range(0,1024):
        if(a>>i&1): product = (product*g)%p
        g = (g*g)%p
    return product

#Miller-Rabin Algorithm
def MRA(p, k):
    if(p<=1): return False
    if(p<=3): return True
    if(p%2==0): return False
    d = p-1
    s = 0
    while d%2==0:
        d//=2
        s+=1
    
    for i in range(k):
        a = random.randint(2, p-1)
        x = FME(a, d, p)
        if(x==1 or x==p-1): return True
        for j in range(s-1):
            x = FME(x,2,p)
            if(x==p-1): break
        else: return False
    return True

#Diffie-Hellman
def DH(p):
    #g and Bkey is given by Server
    a = 105295994554790385529921515371723772242704660365633654571901594321989072089660
    g = 5 
    Akey = FME(g, a, p)
    Bkey = 46382112546454883189136585500170369445484460994330663881511409790809278109877013598493715138108000974411486578681649667960141325572039782807559743119878964632128834381713492229099432061770417447092932015065200430708110180811762686168308476363369387602147183979515009128052848540348642993464546705654545808771
    #Find Shared-Key
    Skey = FME(Bkey, a, p)
    
    #Make Key
    byte_val = Skey.to_bytes(128,'big')
    key = hashlib.sha256(byte_val)
    key = ((key.digest())[:16])
    
    #Decrypt Message
    ciphertext = bytes.fromhex("3ae7c5f767d1a1eb30b99fcf59d554c7137cfef9c84da9a336593b2c748971ab0553b6df6641c2d8ec412ef4cae94d36289f83e5ed5450c0077a8178ba3b60b4f1313066a6a9a86ce4fa9f18d7b2440b867eef52f9145350309ac5453b981ef714f9921c471ed1ba549e85b26b77aefcfbda4ce17d47eac4c74dee0a24f7b4fc138044a1ac9fc5d8060ea72ee4d3b769")
    IV = bytes.fromhex("002465a150fe92935c0f815bdf5f1eab")
    cipher = AES.new(key, AES.MODE_CBC, IV)
    msg = cipher.decrypt(ciphertext).decode('ASCII')
    return msg

p = 179225866959955234276573588861117194756540791358704593468067768684851852182906370963080443002297326255329891339665267800301457170088949698029709362221526908031236897981460646374813727141601927092308207592527527541994180097893675467430614676711646543342782027757613323856825944239133227692261911989289611093063

print("Decrypted Message: ",DH(p))