import hashlib
import socket
from Crypto.Cipher import AES               #The pycryptodome library has the crypto instance which gives many functions in crypto
from Crypto.Util.Padding import pad         # AES is imported to encrypt and decrypt
from Crypto.Util.Padding import unpad       #pad, unpad is is used for padding the last block 
from Crypto.Random import get_random_bytes  #crypto.Random is cryptographically secure random number generator
import hashlib
import sys



#from hashlib import sha256

   
def get_key():
    # N and e client
    Nb = 34777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777790931233333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333336811110763333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333201798777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777743
    eb = 65537
    m=int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",16)
    g=2

    # a generation
    a=int.from_bytes(get_random_bytes(256), byteorder="big")
    print("a = "+str(a))
    # ra generation
    ra = int.from_bytes(get_random_bytes(32), byteorder="big")
    print("ra = "+str(ra))

    ga=pow(g, a, m)
    s.send(int_bytes(ra))
    s.send(int_bytes(ga))
    gb=s.recv(10000)
    gb=int.from_bytes(gb, byteorder='big')
    rb=s.recv(10000)
    rb=int.from_bytes(rb, byteorder='big')
    print("rb = "+str(rb))


    gab = pow(gb, a, m)
    #print("gab= "+str(gab))
    K = hashlib.sha256(str(gab).encode()).hexdigest()
    #print("K= "+K)
    K=bytes(K,encoding='utf8')
    #print("K="+str(K))
    K=K[:32] # only took the first 32 bytes to to be AES compatiable
    print("K = "+str(K))

    # Alice and Bob IDs
    Alice=1111
    Bob=2222

    H=Alice+Bob+ra+rb+ga+gb+gab #Hash

    Hstr=hashlib.sha256(str(H).encode()).hexdigest()
    H_auth=int.from_bytes(bytes(Hstr,encoding='utf8'),byteorder="big")+Bob
    H_Alice=int.from_bytes(bytes(Hstr,encoding='utf8'),byteorder="big")+Alice
    
    #print("K bytes"+str(H_auth))
    Sb=s.recv(10000)
    Sb=int.from_bytes(Sb, byteorder='big')
    #print("Sb encrypted= "+str(Sb))
    Sb=pow(Sb,eb,Nb) # public key verfivation
    #print("Sb plain= "+str(Sb))

    if Sb!=H_auth:
        print("Bob is not authenticated")
        print("Program terminated")# if the recived Sb is not eqaul to the computed hash terminiate the program
        sys.exit()
    else:
        print("Bob is authenticated")

    #print("Sa plain= "+str(H+Alice))
    Sa=pow(H_Alice,d,N)
    s.send(int_bytes(Sa))
    #print("Sa encrypted ="+str(Sa))
    Sa_Alice=str(Sa+Alice)
    Sa_encry=encryptAES_auth(Sa_Alice,K)
    #s.send(Sa_encry)

    #Destroy a
    a=0


    return K

def int_bytes(integer):
    int_str = str(hex(integer))[2:]
    if len(int_str) % 2 == 1:
        int_str = '0' + int_str
    result = bytes.fromhex(int_str)
    return result

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def encryptAES_auth(msg,k):                           #The encryption function it takes a string and returns an encrypted bytes
    msg = bytes(msg,encoding='utf8')
    key=k
    
    #key = bytes.fromhex('95e57754526d259a942f8c5f41f54874335a7a9dd91d941e587d7133982895f6') # KEY 201753170 hashed using sha-256
    cipher = AES.new(key, AES.MODE_ECB) #CBC mode AES the AES takes three parameters key, mode , IV
    return cipher.encrypt(pad(msg,AES.block_size))

def encryptAES(msg):                           #The encryption function it takes a string and returns an encrypted bytes
    msg = bytes(msg,encoding='utf8')
    
    #key = bytes.fromhex('95e57754526d259a942f8c5f41f54874335a7a9dd91d941e587d7133982895f6') # KEY 201753170 hashed using sha-256
    cipher = AES.new(key, AES.MODE_CBC ,IV) #CBC mode AES the AES takes three parameters key, mode , IV
    return cipher.encrypt(pad(msg,AES.block_size)) # pad function will pad if the last generated plaintext block of the file is less than 128 bits long

def decryptAES(msg):                                                                       #The decryption function it takes  bytes and returns a decrypted bytes
    #key= bytes.fromhex('95e57754526d259a942f8c5f41f54874335a7a9dd91d941e587d7133982895f6') # KEY 201753170 hashed using sha-256
    cipher = AES.new(key,AES.MODE_CBC, IV ) #CBC mode AES the AES takes three parameters key, mode , IV
    return unpad(cipher.decrypt(msg),AES.block_size)   #unpad the ciphertext

#Here s represent Server socket, AF_INET = IPv4, Sock_STREAM = TCP
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

# Connect to the ip Address of the Server with port 9000
s.connect(('192.168.16.133',5000))

#get random bytes is secure function from Crypto used to generate 128 bits randomly
IV = get_random_bytes(16)
print("The IV in hex= "+IV.hex())

#313 prime
p=3136666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666313
#328 prime
q=1357911131517193133353739515355575971737577799193959799111113115117119131133135137139151153155157159171173175177179191193195197199311313315317319331333335337339351353355357359371373375377379391393395397399511513515517519531533535537539551553555557559571573575577579591593595597599711713715717719731733735737739751753755757759771
e=9025463
#modinv(e,(p-1)*(q-1))
d=1126105476171470036215354889249911345890783043330728238477856617299326190592892607109833553726293043531900453570622704095263027845633353550307876424024922500255719677848916870750753249873942413619544365598848763716207267456058272532508781430154456817249765597733416823092921574297041364156629601706258564988287984440096762586013623760920611407321338822740274150561266004896327235989245182191075533008588770901244646891814948976437143481096935323888797214360630125922132329585311213661437123266903414620995773703361994568133116691570283348336879185423628694076022879336710404216440173811707505677653858368209853167089490739542060262081830807

N=p*q



key=get_key()


#Client communication
s.send(IV)
hello= 'Hello from Client '

hellocy = encryptAES(hello)#encrypting plaintext
s.send(hellocy) #Send function takes Byte as a parameter that why use encode, encode returns byte represntation  

#Client recv communication 
greetings=s.recv(10000)         #recv(10000).decode(), 10000 is the buffer size. Deocde to string from bytes
print("The greeting ciphertext: "+greetings.hex())
print("The plaintext: "+decryptAES(greetings).decode()) #decrypting ciphertext

#Client communication
game="Guess Game Please"
gamecy = encryptAES(game) #encrypting plaintext
#print(gamecy)
s.send(gamecy)


#Client communication
gamea=s.recv(10000)
print ("The ciphertext :"+gamea.hex())
#print(gamea)
print("The plaintext: "+decryptAES(gamea).decode()) 

running = 1

while running:
    
    #Ask the user for his option
    op1=input("\npress: 1) Start a guessing game round or 2) Quit the guessing game application: ") 
    #test 
    op1T=op1
    s.send(encryptAES(op1T))   #encrypting plaintext
    
     #Send the option to server
    #test
    if op1 == "1":      # in this while loop, we determine whether to play or exit the program
         while running:
                
            guess = input("Enter your guess (between 1 and 100): ")       #Ask the user for his guess     
            s.send(encryptAES (guess)) #Send the guess to server

            response = s.recv(10000)#recive the guess from server

            print("The ciphertext response: "+response.hex())
            print("The plaintext: "+decryptAES(response).decode())
            response=decryptAES(response).decode()
            if response.startswith("Correct"):
               print("Nice Round !!\n")
               op2=input("press: 1) Start a guessing game round or 2) Quit the guessing game application: ") #Here after the guess is correct we ask the user again same to the outer loop to determine whether to quit or continue
               #test
               op2T=op2
               s.send(encryptAES(op2T))
               #Send the option to server
               #test

               #This if statment select the option that the user entered
               if op2 == "1":
                   
                   print("Lets go for another round")
                   IV = get_random_bytes(16)              # Gennerate a new IV for the next round
                   s.send(IV)
                   
                   print("The new IV="+IV.hex())
                   
                   

               else:
                   print("Nice Round, see you again")
                   
                   running=0         


                        
    else:
        print("Thank You See you Again!!")  #if the user quit from the outer loop
        running = 0                          

s.close()
