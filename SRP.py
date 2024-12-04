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

#Calculate hash value in integer
def H(a,b):
    a = a.to_bytes((a.bit_length()+7)//8, 'big')
    b = b.to_bytes((b.bit_length()+7)//8, 'big')
    hash = hashlib.sha256(a+b).digest()
    hash = int.from_bytes(hash, 'big')
    return hash

#Calculate H(p)^H(g)
def pxg_byte(p,g):
    p = p.to_bytes((p.bit_length()+7)//8, 'big')
    g = g.to_bytes((g.bit_length()+7)//8, 'big')

    p = int.from_bytes(hashlib.sha256(p).digest(),'big')
    g = int.from_bytes(hashlib.sha256(g).digest(),'big')

    pg_byte = (p^g).to_bytes(((p^g).bit_length()+7)//8, 'big')
    return pg_byte

#SRP
def SRP(p):
    #1. g^a
    a = 105295994554790385529921515371723772242704660365633654571901594321989072089660
    g = 5 
    Akey = FME(g, a, p)
    
    #2-1. int x=H((salt||password)^iterations)
    password = "undiagnosed"
    pw_byte = password.encode('ASCII')
    
    salt = "3aa1ac56"
    salt_byte = bytes.fromhex(salt)
    
    x = hashlib.sha256(salt_byte+pw_byte).digest()
    for i in range(999):
        x = hashlib.sha256(x).digest()
    x = int.from_bytes(x, 'big')
    
    #2-2. int k=H(p||g) and g^b
    k = H(p, g)

    B = 147830845098832831892306681824808057281292347170321031270137216152806738560698299073747681629932526951461621177044398603674889997292305130230812378200745270391229583109439064318606393588778255087155542872203367144525287890722166637341597060873718859405203990204397178906793173524693344657437533163161856830320
    v = FME(g, x, p)
    Bkey = (B-(k*v))%p

    #2-3. u=H(g^a||g^b)
    u = H(Akey, Bkey)

    #2-4. Shared Key
    Skey = FME(Bkey, a+(u*x), p)

    #3&4. M1 and M2
    Skey_byte = Skey.to_bytes((Skey.bit_length()+7)//8, 'big')
    netId = "jkim172"
    netId_hash = hashlib.sha256(netId.encode('ASCII')).digest()

    Akey_hash = Akey.to_bytes((Akey.bit_length()+7)//8, 'big')
    Bkey_hash = Bkey.to_bytes((Bkey.bit_length()+7)//8, 'big')
    M1 = (hashlib.sha256(pxg_byte(p,g)+netId_hash+salt_byte+Akey_hash+Bkey_hash+Skey_byte).digest()).hex()
    M2 = (hashlib.sha256(Akey_hash+bytes.fromhex(M1)+Skey_byte).digest()).hex()
    return M1, M2

p = 233000556327543348946447470779219175150430130236907257523476085501968599658761371268535640963004707302492862642690597042148035540759198167263992070601617519279204228564031769469422146187139698860509698350226540759311033166697559129871348428777658832731699421786638279199926610332604408923157248859637890960407

M1, M2 = SRP(p)
print("M1: ", M1)
print("M2: ", M2)