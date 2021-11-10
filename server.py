import socket
import sys
import threading
from Crypto.Cipher import DES3
from Crypto import Random
import uuid
import hashlib
CLIENT_LIMIT = 20
MSG_LIMIT = 1024

class User_Info:
    def __init__(self):
        self.__users={}
    def add_user(self, username, password, IP, port):
        self.__users[username]={
            "password": password,
            "IP": IP,
            "port": port,
            "active": False,
            "groups": []
        }
    def get_user(self, username):
        return self.__users[username]
    def exists(self, username):
        return username in self.__users
    def check_password(self, username,user_password):
        if user_password.strip()==self.__users[username]["password"]:
            return True
        else:
            return False
    def do_user_active(self,username):
        self.__users[username]["active"]=True
    def add_clients_server(self,username,IP,port):
        self.__users[username]["IP"]=IP
        self.__users[username]["port"]=port

    def check_user_active(self,username):
        return(self.__users[username]["active"])
    def get_client_address(self,username):
        return(self.__users[username]["IP"]+":"+self.__users[username]["port"])
    def add_group(self, username, group_name):
        self.__users[username]["groups"].append(group_name)


    def get_ip_port(self,username,peers):
        ip_port=""
        for peer in peers:
            if username == peer:
                continue
            ip_port= ip_port+self.get_client_address(peer)+";"
        return ip_port[:-1]    
    

class Group_Info:
    def __init__(self):
        self.__groups={}
    def create_group(self, group_name, owner):
        self.__groups[group_name]={
            "owner": owner,
            "peers": [owner],
            "grp_nonce": b''
        }
        




    def add_member(self, group_name, username):
        self.__groups[group_name]["peers"].append(username)
    def group_exists(self, group_name):
        return group_name in self.__groups
    def list_groups(self):
        response = ""
        for group_name in self.__groups.keys():
            response += group_name + ":" + str(len(self.__groups[group_name]["peers"])) + ","
        return response[:-1]
    
    def check_user_in_group(self,group_name,username):
        
        return username in self.__groups[group_name]["peers"]
    def get_peers(self,group_name):
        return self.__groups[group_name]["peers"]
    

    def generate_key(self,group_name):
        grp_nonce=uuid.uuid1()
        key = str(grp_nonce.int)
        #print(key)
        m=hashlib.md5()
        m.update(key.encode())
        key= m.digest()[:16]
        self.__groups[group_name]["grp_nonce"]=key


    def get_key(self,group_name):
        return self.__groups[group_name]["grp_nonce"]



USERS = User_Info()
GROUPS = Group_Info()

def message_parsing(msg):
    command = msg.split()
    response = "Invalid command!"

    if(command[0] == "signup"):
        if(len(command)!=4):
            response = "Error:Wrong number of arguments!"
        elif(USERS.exists(command[1])):
            response = "Error:Already registered!"
        else:
            ip, port = command[3].split(':')
            USERS.add_user(command[1], command[2], ip, port)
            print("Added entry", USERS.get_user(command[1]))
            response = "Signup successful!"


    elif(command[0] == "signin"):
        if(len(command)!=4):
            response = "Error:Wrong number of arguments!"
        elif(USERS.exists(command[1])):
            if(USERS.check_user_active(command[1])):
                response="Error:User is already signed in"

            elif(USERS.check_password(command[1],command[2])):
                    response="Signed in Successfully--Welcome--"
                    ip, port = command[3].split(':')
                    USERS.add_clients_server(command[1],ip,port)
                    USERS.do_user_active(command[1])
                    print("Currntly signed in user:",command[1])
            else:
                response="Error:Wrong Password,Try again!!"
        else:
            response="Error:User not present,signup to continue..."

    elif(command[0] == "create"):
        if(len(command)!=3):
            response = "Error:Wrong number of arguments!"
        elif(USERS.exists(command[2])):
            if(USERS.check_user_active(command[2])):
                if(GROUPS.group_exists(command[1])):
                    response = "Error:Group already exists"
                else:
                    GROUPS.create_group(command[1], command[2])
                    USERS.add_group(command[2], command[1])
                    GROUPS.generate_key(command[1])
                    #tt=GROUPS.get_key(command[1])
                    #print(f"Group details")
                    #print(tt)

                    print("Updated entry for",command[2],USERS.get_user(command[2]))
                    response = "Group created successfully"
            else:
                response = "Error:User not signed in"
        else:
            response = "Error:User not present,signup to continue..."
    
    elif(command[0] == "list"):
        response = GROUPS.list_groups()
        if(response == ""):
            response = "Error:No groups"

    elif "client_info" in command[0]:
        if len(command)!=1:
            response = "Error:Wrong number of arguments!"
        else:
            c,username=command[0].split(":")
            if(not USERS.exists(username)):
                response = "Error:User not present"
            else:
                response=USERS.get_client_address(username)
    
    elif "group_info" in command[0]:
        if len(command)!=1:
            response = "Error:Wrong number of arguments!"
            #print("wrong")
        else:
            g,groupname,username=command[0].split(":")
            if(not GROUPS.group_exists(groupname)):
                response = "Error:Group doesn't exists"
            
            elif(GROUPS.check_user_in_group(groupname,username)==False):
                response = "Error:User not part of group,sorry cannot send messages here"
            else:    
                response=USERS.get_ip_port(username,GROUPS.get_peers(groupname))



    elif(command[0] == "join"):
        if(len(command)!=3):
            response = "Error:Wrong number of arguments!"
        elif( not GROUPS.group_exists(command[1])):
                response="Error:Group doesn't not exists"

        elif(GROUPS.check_user_in_group(command[1],command[2])):
            response="Error:User already present in group-"+command[1]
                    
        else:
            GROUPS.add_member(command[1],command[2])
            USERS.add_group(command[2],command[1])
            response="User joined group-" +command[1]
            print(command[2]+ " added to group "+command[1])

    
    elif("key" in command[0]):
        if len(command)!=1:
            response = "Error:Wrong number of arguments!"
            #print("wrong")
        else:
            key,groupname=command[0].split(":")
            response=GROUPS.get_key(groupname)



    return response

def server(clientsocket, address):
    while(True):
        msg = clientsocket.recv(MSG_LIMIT).decode()
        print("Before parsing msg:", msg)
        if msg=="exit":
            break
        print("Recieved message:", msg)
        msg = message_parsing(msg)
        temp=str(type(msg))
        if "byte" in temp :
            clientsocket.send(msg)
            #print("Byte type")
        else:
            clientsocket.send(msg.encode())
    clientsocket.close()

if( len(sys.argv) != 2):
    print("Incorrect number of command line arguments. Pass IP and Port!")
    exit()
ip, port = sys.argv[1].split(':')
serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serversocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
serversocket.bind((ip, int(port)))
serversocket.listen(CLIENT_LIMIT)
while(True):
    (clientsocket, address) = serversocket.accept()
    print("Connected to",address)
    t1 = threading.Thread(target=server, args=(clientsocket, address,)) 
    t1.start() 
serversocket.close()