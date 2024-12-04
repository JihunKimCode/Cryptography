import random

#Fast Modular Exponentiation
def FME(g, a, p):
    product = 1
    g = g%p
    for i in range(0,2048):
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

#Extended Euclidean Algorithm
def EEA(a,b):
    t1 = 0; t2 = 1

    while b:
        q = a//b
        r = a%b
        a = b; b = r

        t = t1-q*t2
        t1 = t2; t2 = t

    if(t1<0): t1+=a
    return t1

def RSA():
    p = 105305463030127717898602484131089018279879570850041347274954607820599385764100738670989924338538631561564022373057488545405646013734284677660679989702733610632627979120634712176335175587769960423813559148735629761382467808276945263721283402906884602960895182528854613688847409931107042166665095707057790244263
    q = 108197420422193755193689051277153457492971247450038179733893231442250680051692136444044698656376831156308759880250121564652604913275015062598422229103073515926461739905439365704539789610347269979192940858747603035623467198674813300665692873923107783854419189629927495972662664159830351557779326048938962371011
    n = p*q
    Euc = (p-1)*(q-1)
    e = 65537
    d = EEA(Euc,e)
    
    #Encrypt Message
    plaintext = int.from_bytes("singspiel".encode('ASCII'), 'big')
    encrypt = FME(plaintext, e, n)

    #Decrypt Message
    ciphertext = 3183762432492608684496860060803762518199878608016688497857024494519673545178695218598749186351658442385351879996622044257522287237085726395287171246527827810900239310820381446253331247094445052763154467805496322343046785185545744622686811509432971057253344680366040123120854916586574236686662893282022678373159679885555434879436861162078773986153569651156549439972105233330278532482906054677588976260131044772425328930097989649332674007662106897051914162051262775126322206204055072810881553768593124858336930899535482045477233852841796037140465716622608653617224765690434556818126835659480479244824597437957942660336
    decrypt = FME(ciphertext, d, n)
    decrypt = decrypt.to_bytes(128,'big').decode('ASCII')
    return encrypt, decrypt

enc, dec = RSA()
print("Encrypted Message:", enc)
print("Decrypted Message:", dec)