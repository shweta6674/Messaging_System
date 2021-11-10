import socket
import sys
import threading
import os
from Crypto.Cipher import DES3
from Crypto import Random
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import hashlib
import binascii

# Global constants
CLIENT_LIMIT = 20
MSG_LIMIT = 1024
PRIME = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF
GENERATOR = 2

# Global variables
username = ""
group_key = {}

class DES:
    def generate_random_number(self, size_in_bytes):
        return get_random_bytes(size_in_bytes)

    def generate_key_DHK(self, username):
        # seed_1 = int(binascii.hexlify(get_random_bytes(10)+bytes(username.encode())), base=16)
        # private_key = hashlib.sha256(str(seed_1).encode()).hexdigest()
        # shared_key_1 = diffie_hellman_key_exchange(int(private_key, base = 16), client_socket)
        # print("shared key 1, client:", shared_key_1)
        
        usern = username
        username_size = len(usern)
        if(username_size>112):
            usern = usern[:112]
            key = usern.encode()
        elif(username_size<112):
            if(username_size%8):
                l1 = 8 - username_size%8
                for _ in range(l1):
                    usern += 'a'
            if(len(usern)<112):
                usern = PBKDF2(usern, self.generate_random_number(int((112-len(usern))/8)), dkLen=24)
                key = usern
            else:
                key = usern.encode()                                                                                                                                                                                                                                                                            
        else:
            key = usern.encode()
        return bytes.fromhex(hashlib.sha256(key).hexdigest()[:48])

    def encrypt(self, plaintext, key, file_flag=False):
        # key should be of bytes datatype
        iv = Random.new().read(DES3.block_size) #DES3.block_size==8
        cipher_encrypt = DES3.new(key, DES3.MODE_OFB, iv)

        # Pad plaintext to make its length multiple of 8
        pad_length = 8 - len(plaintext) % 8
        if pad_length != 8:
            for i in range(pad_length):
                if file_flag:
                    plaintext = plaintext + b'0'
                else:
                    plaintext = plaintext + " "

        if(file_flag):
            # if encryption is for file data, do not convert plaintext to bytes. Plaintext is already in bytes format.
            return str(cipher_encrypt.encrypt(plaintext).hex()), iv
        return str(cipher_encrypt.encrypt(plaintext.encode()).hex()), iv
    
    def decrypt(self, ciphertext, key, iv, file_flag=False):                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        
        ciphertext = bytes.fromhex(ciphertext)
        cipher_decrypt = DES3.new(key, DES3.MODE_OFB, iv)
        if(file_flag):
            # Return bytes for file data
            return cipher_decrypt.decrypt(ciphertext) 
        return cipher_decrypt.decrypt(ciphertext).decode()

DES_OBJ=DES() # Single object to be used for encryption/decryption

# Function used by sender for DHK
def diffie_hellman_key_exchange(private_key, sender_client_socket):

    public_key = pow(GENERATOR, private_key, PRIME)
    msg = ":".join(["dhk", str(public_key)[:1010]])
    sender_client_socket.send(msg.encode())

    msg = sender_client_socket.recv(MSG_LIMIT).decode()
    msg = msg.split(":")
    public_key = msg[1]
    shared_key = pow(int(public_key), private_key, PRIME)
    shared_key = hashlib.sha256(str(shared_key).encode()).hexdigest()

    return shared_key

# Function used by reciever for DHK
def diffie_hellman_key_exchange_reciever(private_key, sender_client_socket):

    public_key = pow(GENERATOR, private_key, PRIME)
    msg = ":".join(["dhk", str(public_key)[:1010]])
    sender_client_socket.send(msg.encode())

# Prints error message on the terminal if error returned from server
def print_if_error(msg):
    msg=str(msg)
    if msg.split(":")[0].strip() == "Error":
        print(msg.split(":")[1].strip())
        return True
    return False

def print_groups_list(msg):
    for group_info in msg.split(","):
        group_name, num_members = group_info.split(":")
        print(group_name + ": has " + str(num_members) + " member(s)")


def send_message_to_peer(peer_ip, peer_port, user_name, msg, is_file = False, filename = None, group_name = None):
    sender_client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sender_client_socket.connect((peer_ip, int(peer_port)))
    
    flag=0
    if group_name!=None:
        user_name=group_name
        flag=1
    
    if is_file:
        if os.path.exists(filename):
            file_contents = open(filename,'rb')

            # File encryption for p2p
            if flag==0:
                private_key = DES_OBJ.generate_key_DHK(user_name)
                shared_key = diffie_hellman_key_exchange(int.from_bytes(private_key, byteorder='big'), sender_client_socket)
                        
                msg=":".join([user_name, "client_sending", str(is_file), filename])
                msg=msg.encode()
                sender_client_socket.send(msg)
                
                msg=sender_client_socket.recv(MSG_LIMIT).decode()
                if msg=="confirm":
                    l=file_contents.read(MSG_LIMIT)
                    while l:
                        encrypted_message, iv = DES_OBJ.encrypt(l, shared_key[:24], True)
                        sender_client_socket.send(encrypted_message.encode())
                        msg=sender_client_socket.recv(MSG_LIMIT).decode()

                        if msg=="send_iv":
                            sender_client_socket.send(iv)
                        
                        msg=sender_client_socket.recv(MSG_LIMIT).decode()
                        if msg=="ack":
                            l=file_contents.read(MSG_LIMIT)
                return
            
            #File encryption for Group Sending
            else:
                msg=":".join([user_name, "group_sending", str(is_file), filename])
                msg=msg.encode()
                sender_client_socket.send(msg)

                msg=sender_client_socket.recv(MSG_LIMIT).decode()
                if msg=="confirm":
                    l=file_contents.read(MSG_LIMIT)
                    while l:
                        enc_msg, iv=DES_OBJ.encrypt(l, group_key[user_name], True)
                        sender_client_socket.send(enc_msg.encode())
                        msg=sender_client_socket.recv(MSG_LIMIT).decode()

                        if msg=="send_iv":
                            sender_client_socket.send(iv)

                        msg=sender_client_socket.recv(MSG_LIMIT).decode()
                        if msg=="ack":
                            l=file_contents.read(MSG_LIMIT)
            file_contents.close()
            return
        else:
            print("File does not exist!")
            return

    # p2p text message
    if flag==0:
        private_key = DES_OBJ.generate_key_DHK(user_name)
        shared_key = diffie_hellman_key_exchange(int.from_bytes(private_key, byteorder='big'), sender_client_socket)
        encrypted_message, iv = DES_OBJ.encrypt(msg, shared_key[:24])

        msg = ":".join([user_name, "client_sending", str(is_file), "", str(len(msg)), encrypted_message])
        sender_client_socket.send(msg.encode())

        msg=sender_client_socket.recv(MSG_LIMIT).decode()
        if msg=="send_iv":
            sender_client_socket.send(iv)
            return

    # group text message
    else:
        enc_msg, iv=DES_OBJ.encrypt(msg, group_key[user_name])
        msg = ":".join([user_name, "group_sending", str(is_file), "", str(len(msg)), enc_msg])
        sender_client_socket.send(msg.encode())

        msg=sender_client_socket.recv(MSG_LIMIT).decode()
        if msg=="send_iv":
            sender_client_socket.send(iv)
            return


# received message format => username:client/group_sending:is_file:file_name (if message is file)
# received message format => username:client/group_sending:is_file::msg_length:iv:message (if message is text)

# recieved message format => dhk:public_key
def server(clientsocket, address):
    msg = clientsocket.recv(MSG_LIMIT).decode()
    msg = msg.split(":")
    filename = ""
    f = None
    shared_key = ""

    # message is dhk exchange
    if msg[0] == "dhk":
        public_key = msg[1]
        private_key = DES_OBJ.generate_key_DHK(username)
        diffie_hellman_key_exchange_reciever(int.from_bytes(private_key, byteorder='big'), clientsocket)
        shared_key = pow(int(public_key), int.from_bytes(private_key, byteorder='big'), PRIME)
        shared_key = hashlib.sha256(str(shared_key).encode()).hexdigest()
        msg = clientsocket.recv(MSG_LIMIT).decode()
        msg = msg.split(":")
    
    # message is file
    if msg[2] == "True":
        sender=msg[0]

        # File decryption from client
        if msg[1]=="client_sending":
            filename=username+"/received_from_"+sender+"_"+msg[3]
            with open(filename,'wb') as f:
                clientsocket.send("confirm".encode())
                while True:
                    msg=clientsocket.recv(2*MSG_LIMIT).decode()
                    
                    if not msg:
                        break
                    
                    clientsocket.send("send_iv".encode())
                    iv=clientsocket.recv(MSG_LIMIT)

                    msg=DES_OBJ.decrypt(msg, shared_key[:24], iv, True)
                    f.write(msg)
                    clientsocket.send("ack".encode())
            f.close()
        
        # File decryption from group
        else:
            filename=username+"/received_from_group_"+sender+"_"+msg[3]
            with open(filename,'wb') as f:
                clientsocket.send("confirm".encode())
                while True:
                    msg=clientsocket.recv(2*MSG_LIMIT).decode()

                    clientsocket.send("send_iv".encode())
                    iv=clientsocket.recv(MSG_LIMIT)

                    if not msg:
                        break

                    msg=DES_OBJ.decrypt(msg, group_key[sender], iv, True)
                    clientsocket.send("ack".encode())
                    f.write(msg)
            f.close()
        print("File recieved from {}: {} \n>>".format(sender, filename), end="")
    
    # message is text
    else:
        sender = msg[0]
        msg_got=""

        # Text message decryption from client
        if msg[1]=="client_sending":
            msg_got=msg[5]
            clientsocket.send("send_iv".encode())
            iv=clientsocket.recv(MSG_LIMIT)
            msg_got=DES_OBJ.decrypt(msg_got, shared_key[:24], iv, False)

        # Text message decryption from group
        else:
            #Do decryption of text sent from GROUP, at msg[5]
            msg_got=msg[5]
            clientsocket.send("send_iv".encode())
            iv=clientsocket.recv(MSG_LIMIT)
            msg_got=DES_OBJ.decrypt(msg_got, group_key[sender], iv, False)
        print("Message recieved from {}: {} \n>>".format(sender, msg_got), end="")

    clientsocket.close()

def server_main(client_ip, client_port):
    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serversocket.bind((client_ip, int(client_port)))
    serversocket.listen(CLIENT_LIMIT)
    while(True):
        (clientsocket, address) = serversocket.accept()
        t1 = threading.Thread(target=server, args=(clientsocket, address,)) 
        t1.start()     
    serversocket.close()

def client_main(server_ip, server_port, client_ip, client_port):
    global username
    clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    clientsocket.connect((server_ip, int(server_port)))
    while(True):
        msg = input(">>")

        # Exit
        if(msg=="exit"):
            clientsocket.send(msg.encode())
            break

        # Signup
        if(msg.split()[0]=="signup"):
            msg += " "+client_ip+":"+client_port
            clientsocket.send(msg.encode())
            msg = clientsocket.recv(MSG_LIMIT).decode()
            if not print_if_error(msg):
                print("Signup successful!")
            continue

        # Signin
        if(msg.split()[0]=="signin"):
            username = msg.split()[1]
            msg += " "+client_ip+":"+client_port
            clientsocket.send(msg.encode())
            msg = clientsocket.recv(MSG_LIMIT).decode()
            if not print_if_error(msg):
                print("Signin successful!")
                check=os.path.isdir(username)
                if not check:
                    os.makedirs(username)
            continue

        # List groups
        if msg.strip().lower() == "list":
            clientsocket.send(msg.strip().lower().encode())
            msg = clientsocket.recv(MSG_LIMIT).decode()
            if not print_if_error(msg):
                print_groups_list(msg)
            continue

        # Join groups
        if msg.split()[0].lower() == "join" and username!="":
            target=msg.split()[1][:]
            check="list"
            join_flag=False
            clientsocket.send(check.strip().lower().encode())
            check=clientsocket.recv(MSG_LIMIT).decode()
            if not print_if_error(check):
                for i in check.split(","):
                    i=i.split(":")[0]
                    if i==target:
                        msg+=" "+username
                        clientsocket.send(msg.strip().lower().encode())
                        msg=clientsocket.recv(MSG_LIMIT).decode()
                        if not print_if_error(msg):
                            print("Joined group", target, "successfully!")
                            join_flag=True
                            msg="key:"+target
                            clientsocket.send(msg.strip().lower().encode())
                            group_key[target]=clientsocket.recv(MSG_LIMIT)
                        break
            if join_flag==False:
                msg="create "+target+" "+username
                clientsocket.send(msg.strip().lower().encode())
                msg=clientsocket.recv(MSG_LIMIT).decode()
                if not print_if_error(msg):
                    print("Group", target, "created and joined successfully!")
                    msg="key:"+target
                    clientsocket.send(msg.strip().lower().encode())
                    group_key[target]=clientsocket.recv(MSG_LIMIT)
            continue

        # Create group
        if msg.split()[0].lower() == "create" and username!="":
            target=msg.split()[1][:]
            msg+=" "+username
            clientsocket.send(msg.strip().lower().encode())
            msg=clientsocket.recv(MSG_LIMIT).decode()
            if not print_if_error(msg):
                print("Group", target, "created and joined successfully!")
                msg="key:"+target
                clientsocket.send(msg.strip().lower().encode())
                group_key[target]=clientsocket.recv(MSG_LIMIT)
            continue

        # Send message (p2p and group)
        if msg.split()[0].lower() == "send" and username!="":
            msg = msg.split()
            group_flag=False
            g_list=[]
            g_info_name=[]
            g_info=[]
            if msg[1].strip().lower()=="group":
                g_list=msg[2].split(",")
                g_info=[]
                g_info_name=[]
                for x in range(len(g_list)):
                    req_msg="group_info:"+g_list[x].lower()+":"+username
                    group_flag=True
                    clientsocket.send(req_msg.strip().lower().encode())
                    resp_msg=clientsocket.recv(MSG_LIMIT).decode()
                    if not print_if_error(resp_msg):
                        g_info.append(resp_msg)
                        g_info_name.append(g_list[x])
            else:
                req_msg = "client_info:" + msg[1].strip().lower()
                clientsocket.send(req_msg.strip().lower().encode())
                resp_msg = clientsocket.recv(MSG_LIMIT).decode()
            if group_flag==False and not print_if_error(resp_msg):
                peer_ip, peer_port = resp_msg.split(":")
                if msg[2].strip().lower() == "file":
                    send_message_to_peer(peer_ip, peer_port, username, None, True, msg[3].strip())
                else:
                    send_message_to_peer(peer_ip, peer_port, username, " ".join(msg[2:]), False)

            if group_flag==True and not print_if_error(resp_msg):
                group_flag=False
                if len(resp_msg)!=0:
                    for x in range(len(g_info_name)):
                        resp_msg=g_info[x].split(";")
                        for member in resp_msg:
                            peer_ip, peer_port=member.split(":")
                            if msg[3].strip().lower() == "file":
                                send_message_to_peer(peer_ip, peer_port, username, None, True, msg[4].strip(), group_name=g_info_name[x])
                            else:
                                send_message_to_peer(peer_ip, peer_port, username, " ".join(msg[3:]), False, group_name=g_info_name[x])
                else:
                    print("Group does not have other users!")
            continue

        else:
            print("Invalid command!")

    clientsocket.close()

if( len(sys.argv) != 3):
    print("Incorrect number of command line arguments. Pass IP and Port!")
    exit()
server_ip, server_port = sys.argv[1].split(':')
client_ip, client_port = sys.argv[2].split(':')

t1 = threading.Thread(target=client_main, args=(server_ip, server_port, client_ip, client_port)) 
t2 = threading.Thread(target=server_main, args=(client_ip, client_port,)) 
t1.start()
t2.start()