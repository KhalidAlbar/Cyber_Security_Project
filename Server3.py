import socket #Socket library the responisole for socket communication
import random #Random to generate a random number for the Game
from Crypto.Cipher import AES                #The pycryptodome library has the crypto instance which gives many functions in crypto
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hashlib
import sys

def get_key():
    # public keys
    Na = 4259314582525595794952896279831989964683535696805053903211858137750697007987600546826470783730009622600246526139085396375988935215173152765711991635948895174787765411691304250561541154100380024337283563176467780727006619597243523136082393372985932211856169115395007985631911524471095742021634580891871484430709874419710380259176873894124735911297995476651685069551047702994953578867289247873165120208834126084706461753712337626048006631923843565524149441396485110402360982738029988613902324282908200155243869161119706094720011970592347639598223511933892517809764853478770729351106398356982235290582541166454876835460752707796421713672294323
    ea = 9025463
    ra=c.recv(10000)
    ra = int.from_bytes(ra, byteorder='big')
    print("ra = "+str(ra))
    ga=c.recv(10000)
    ga = int.from_bytes(ga, byteorder='big')
    m=int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",16)
    g=2
    b=int.from_bytes(get_random_bytes(256), byteorder="big")
    print("b = "+str(b))
    rb= int.from_bytes(get_random_bytes(32), byteorder="big")
    print("rb = "+str(rb))
    gb=pow(g, b, m)
    c.send(int_bytes(gb))
    c.send(int_bytes(rb))
    gab = pow(ga,b,m)
    #print("gab= "+str(gab))
    K =hashlib.sha256(str(gab).encode()).hexdigest()
    #print("K= "+K)
    K=bytes(K,encoding='utf8')
    #print("K bytes"+str(K))
    K=K[:32]
    print("K = "+str(K))

    Alice=1111
    Bob=2222

    H=Alice+Bob+ra+rb+ga+gb+gab
    H=hashlib.sha256(str(H).encode()).hexdigest()
    H_Bob=int.from_bytes(bytes(H,encoding='utf8'),byteorder="big")+Bob
    H_Alice=int.from_bytes(bytes(H,encoding='utf8'),byteorder="big")+Alice
    #print("HH"+str(H_Alice))
    #print("Sb plain= "+str(H_Bob))
    Sb=pow(H_Bob,d,N)
    c.send(int_bytes(Sb))
    #print("Sb = "+str(Sb))
    Sa=c.recv(10000)
    #Sa_enc=c.recv(10000)
    #print("Sa= "+str(Sa))
    #Sa_dec=decryptAES_auth(Sa_enc,K).decode()
    #print("Sa= "+Sa_dec)
    Sa=int.from_bytes(Sa, byteorder='big')
    Sa=pow(Sa,ea,Na)
    #print("Sa plain ="+str(Sa))

    if Sa!=H_Alice:
        print("Alice is not authenticated")
        print("Program terminated")
        sys.exit()
    else:
        print("Alice is authenticated")    

    #Destroy b
    b=0


    return K
    


def int_bytes(integer):
    int_str = str(hex(integer))[2:]
    if len(int_str) % 2 == 1:
        int_str = '0' + int_str
    result = bytes.fromhex(int_str)
    return result    



def decryptAES(msg):           #The decryption function it takes  bytes and returns a decrypted bytes
    #key= bytes.fromhex('95e57754526d259a942f8c5f41f54874335a7a9dd91d941e587d7133982895f6')
    cipher = AES.new(key,AES.MODE_CBC, IV ) #CBC mode AES the AES takes three parameters key, mode , IV
    return unpad(cipher.decrypt(msg),AES.block_size)

def encryptAES(msg):             #The encryption function it takes a string and returns an encrypted bytes
    msg = bytes(msg,encoding='utf8')
    
    
    #key = bytes.fromhex('95e57754526d259a942f8c5f41f54874335a7a9dd91d941e587d7133982895f6')
    cipher = AES.new(key, AES.MODE_CBC ,IV) #CBC mode AES the AES takes three parameters key, mode , IV
    return cipher.encrypt(pad(msg,AES.block_size))    

#Here s represent Server socket, AF_INET = IPv4, Sock_STREAM = TCP
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

#In the server we bind the address with the socket to form a new connection
s.bind(("192.168.16.133",5000))
#Listen for 5 clients
s.listen(5)
print ("Waiting for client ...")


(c,a) = s.accept()# accept The client and returns the a= address and c= socket
print ("Received connection from", a)

p = 313_0000000000_0000000000_0000000000_0000000000_0000000000_0000000000_0000000000_0000000000_0000000000_0000000000_0000000000_0000000000_0000000000_0000000000_0000000000_1183811000_0000000000_0000000000_0000000000_0000000000_0000000000_0000000000_0000000000_0000000000_0000000000_0000000000_0000000000_0000000000_0000000000_0000000000_0000000313
q = 1111111_1111111111_1111111111_1111111111_1111111111_1111111111_1111111111_1111111111_1111111111_1111111111_1111111111_1111111111_1111111111_1111111111_1111111111_1111111111_1111111111_1111111111_1111111111_1111111111_1111111111_1111111111_1111111111_1111111111_1111111111_1111111111_1111111111_1111111111_1111111111_1111111111_1111111111_1111111111
e = 65537
d = 31435689423955594210564685258369741943906156488361960080226097895506016109644594317374578906232781143137125254097346197991634920392721329596682450795394640538555799522915808372878424910101672846381942007313934622172716684214006337387023106540325821037480100299576320755196809944509717157229249635066196703134619202816637623361188675438641106889577219314619561808172821798712516932758933460827047655861913456859823034655572000888387051928257659371381391003894322630303830573606769560197547441394428592499910991755293447467333974192695220511568528719145927745650039926555482653564653045862133858227667831403125969554094124947230513
N = p * q
#key=bytes("197a0f342235fd838a9b36c2bdac0f6a" ,encoding='utf8')
key=get_key()
#Client communication
IV=c.recv(10000)
print("The IV in hex is ="+IV.hex())

hello=c.recv(10000)

print("Hello in ciphertext hex: "+hello.hex()) #print the ciphertext
print("Hello in plaintext: "+decryptAES(hello).decode()) #decrypte the ciphertext

greetings="Greetings!"
c.send(encryptAES(greetings))

game= c.recv(10000)
print("The ciphertext: "+game.hex())
print("The IV is ="+IV.hex())
print("The plaintext: "+decryptAES(game).decode())

ready="Ready For The Guess Game!"
c.send(encryptAES(ready)) #encrypt the plaintext


random_number = random.randint(1, 100) #Create a random number

running = 1

while running:# this while loop, we determine whether to play or exit the program if running = 0 we exit and close the communcation

    optS=c.recv(10000)#Recive the option from the client
    optS= decryptAES(optS).decode()
    
    if optS == "1": # When 1 we play the game

        while optS == "1": #Inner loop becuase the option again after he choose a correct guess
            
            guessC=c.recv(10000)  #reciving the guess
            guessP= decryptAES(guessC).decode()
            guess=int(guessP)# change from string to int to compare
            print("The ciphertext guess: "+guessC.hex())

            print("The plaintext guess: ")
            print(guess)

            # Guess Game logic
            if guess < random_number:
                far_message="Higher!"
                c.send(encryptAES(far_message))

            if guess > random_number:
                far_message="Lower!"
                c.send(encryptAES(far_message))

            if guess == random_number:
                correct_message="Correct!"
                c.send(encryptAES(correct_message))
                print("CorrecT")
                random_number = random.randint(1, 100)# create a new random number for the next round 
                optS=c.recv(10000)# Recive the option from the user to continue or quit
                optS=decryptAES(optS).decode()
                IV=c.recv(10000)
                print("The new IV is= "+IV.hex())
                
                
                
               
                
                if optS=="2":#if the user quit  
                    running=0
                    
                

    elif optS == "2":#if the user quit from the outer loop
      print("exit")
      running=0
      
    

c.close()#if the user quit close the socket 
