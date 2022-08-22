import os
import time
import socket
import hashlib
import base64
import random
import re
import threading
from requests import get
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from mycryptfunc import *

servers = ["SERVER"]
admins = ["ADMIN", "SERVER"]

hostip = input("Enter server's IP adress (default = 127.0.0.1) -> ")
if hostip == "" or hostip.isspace():
    hostip = '127.0.0.1'

port = input("Enter server's port (default = 55555) -> ")
if port == "" or port.isspace():
    port = 55555

def hashpwd(password, times=1):
    for i in range(0,times):
        h = hashlib.new('sha256')
        h.update(password.encode('utf-8'))
        password = h.hexdigest()
    return h.hexdigest()

mode = input("/login (default), /register or /delete -> ").lower()

if "login" in mode:
    operation = 'LOGIN'
    command = 'LOGIN'

elif "register" in mode:
    operation = 'REGISTER'
    name_to_reg = input("Choose a nickname -> ")
    name_to_reg = re.sub(r"[^a-zA-Z0-9 _àèìòù+&£$€@#]","",name_to_reg)
    name_to_reg = name_to_reg.strip()
    if name_to_reg == "" or name_to_reg.isspace() or name_to_reg == ": ":
        name_to_reg = "user" + str(random.randint(10000, 99999))
    name_to_reg = name_to_reg[:min(len(name_to_reg), 20)]
    name_to_reg = name_to_reg.strip()
    name_to_reg = name_to_reg.replace(' ', '_')

    mail_to_reg = input("Email -> ")
    mail_to_reg = re.sub(r"[^a-zA-Z0-9_~+@\.\-]","",mail_to_reg)
    mail_to_reg = mail_to_reg.strip()

    pwd_to_reg = input("Password -> ")
    pwd_to_reg = hashpwd(pwd_to_reg, 100000)

    command = f'REGISTER {name_to_reg};{mail_to_reg};{pwd_to_reg}'

elif "delete" in mode:
    operation = 'DELETE'
    mail_to_del = input("Email -> ")
    mail_to_del = re.sub(r"[^a-zA-Z0-9_~+@\.\-]","",mail_to_del)
    mail_to_del = mail_to_del.strip()
    command = f'DELETE {mail_to_del}'

else:
    operation = 'LOGIN'
    command = 'LOGIN'


if operation == 'LOGIN':
    nickname = input("Your nickname -> ")
else:
    nickname = "isarandomnick"

# Clean nickname
nickname = re.sub(r"[^a-zA-Z0-9 _àèìòù+&£$€@#]","",nickname)
nickname = nickname.strip()
if nickname == "" or nickname.isspace() or nickname == ": ":
    nickname = str(random.randint(10000, 99999))
nickname = nickname[:min(len(nickname), 20)]
nickname = nickname.strip()
nickname = nickname.replace(' ', '_')

if operation == 'LOGIN':
    password = input("Password for profile (leave blank if not required) -> ")
else:
    password = "isarandompass"

password = hashpwd(password, 100000)

# Connecting To Server
print("Connecting...")
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((hostip, int(port)))
print("Making requests...")


stop_thread = False
tls_key = bytes(0)

# Get timestamp
def timestamp():
    time_tuple = time.localtime()
    time_string = time.strftime("%Y/%m/%d %H:%M:%S", time_tuple)
    return ("[" + time_string + "]")

def ec(string):
    global tls_key
    if tls_key != bytes(0):
        string = myencrypt(string, tls_key)
        string = string.encode('utf-8')
        return string
    else:
        return string.encode('utf-8')

def dc(token):
    global tls_key
    if tls_key != bytes(0):
        token = mydecrypt(token, tls_key)
        return token
    else:
        return token

# Listening to Server and Sending Nickname
def receive():
    while True:
        global stop_thread
        global tls_key
        if stop_thread:
            break
        try:
            # Receive Message From Server
            message = client.recv(8192).decode('utf-8')
            #print(tls_key, message) #debug 
            message = dc(message)
    
            if message == 'CLTKEY':
                clt = DiffieHellman()
                client.send(str(clt.publicKey).encode('utf-8'))
                client.send('SRVKEY'.encode('utf-8'))
                srv_key = client.recv(2048).decode('utf-8')
                clt.generateKey(int(srv_key))
                tls_key = clt.getKey()

                if tls_key != bytes(0):
                    dig = hashlib.sha256(bytes(str(srv_key).encode('utf-8')))
                    salt = bytes(dig.digest()[:32])
                    kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA512(),
                    length=32,
                    salt=salt,
                    iterations=350000,
                    )
                    tls_key = base64.urlsafe_b64encode(kdf.derive(tls_key))

                    # Validate encryption
                    client.send('VERTLS'.encode('utf-8'))
                    vercode = int(dc(client.recv(1024).decode('utf-8')))
                    vercode *= vercode
                    client.send(ec(str(vercode)))
                    response = dc(client.recv(1024).decode('utf-8'))
                    print(response)

            elif message == 'CMD':
                client.send(ec(command))
            
            elif message == 'NICK':
                client.send(ec(nickname))
                
            elif message == 'PASS':
                client.send(ec(password))

            elif message == 'REFUSE':
                print("Connection refused! Wrong data!")
                client.close()
                stop_thread = True

            elif message == 'DOUBLE':
                print("Another user with your data is already present!")
                client.close()
                stop_thread = True

            elif message == 'BAN':
                print("Banned from the server!")
                client.close()
                stop_thread = True

            elif message == 'CLOSED':
                print("Server closed or not available!")
                client.close()
                stop_thread = True 

            elif message == 'DONE':
                print("Operation completed!")
                client.close()
                stop_thread = True  

            else:
                if message != "" and not message.isspace():
                    print(timestamp(), message)

        except:
            # Close Connection When Error
            print("An error occured!")
            client.close()
            break
        
def write():
    global stop_thread
    global tls_key
    while True:
        if stop_thread:
            break
        try:
            message = '{}: {}'.format(nickname, input(''))
        except:
            print("Message not delivered")
        if message[len(nickname)+2:].startswith('/'):
            
            if message[len(nickname)+2:].startswith('/help'):
                print('''
LIST OF COMMANDS:              |PERMISS.|DESCRIPTION                 
/help                           (client) Print the list of commands
/settings help                  (server) Print the list of server's commands and settings
/list                           (client) Print the list of online users
/admins                         (client) Print the list of admins
/mtlist                         (admins) Print the list of muted users
/blacklist                      (admins) Print the list of banned users
/dm <user>; <message>           (client) Send <message> only to <user> 
/op <user>                      (server) Gives <user> admin's permissions
/deop <user>                    (server) Remove <user> admin's permissions
/mute <user>                    (admins) Mute <user>
/unmute <user>                  (admins) Unmute <user>
/kick <user>                    (admins) Disconnect <user>
/ban <user>                     (admins) Ban <user>
/unban <user>                   (admins) Unban <user>
/donut                          (donuts) It's a donut!
/publicip                       (client) Print your IP adress
/ipconfig                       (client) Open terminal and run /ipconfig
/ping <adress>                  (client) Get latency beetween your pc and <adress>
/credits                        (client) Show credits page
/leave                          (client) Disconnect yourself

''')
            elif message[len(nickname)+2:].startswith('/settings'):
                if nickname not in servers:
                    print(timestamp(), "Refused!")
                    continue
                
                if message[len(nickname)+2+10:].startswith('help'):
                    print('''
LIST OF COMMANDS:              |PERMISS.|DEFAULT|DESCRIPTION                 
/settings help                  (server)         Print the list of server's commands and settings
/settings get                   (server)         Print current configuration of the settings
/settings default               (server)         Set all settings to their default configuration
/settings load                  (server)         Load the settings stored in settings.txt
/settings save                  (server)         Save the current settings in settings.txt   
/settings erase                 (server)         Erase saved settings in settings.txt
/settings autoload [true/false] (server)  false  Run "/settings load" when starting the server
/log [true/false/default]       (server)  true   Enable server log
/auth [true/false/default]      (server)  true   Force user's authentication
/open [true/false/default]      (server)  false  Let users (other than SERVER and ADMIN) connect to your server
/users                          (server)         Print the list of registered users
/register <user>; <password>    (server)         Register a user without authentication using <user> and <password>
/deleteprofile <user>           (server)         Delete <user> without authentication

WARNING! EDITING OR DELETING FILES FROM "SERVER" FOLDER (e.g. "login_details.txt") COULD CAUSE A SERVER MALFUNCTION,
         IF YOU HAVE PROBLEMS TRY TO DELETE THE CONTENTS OF TEXT FILES (EXCEPT "autoload.txt" AND "settings.txt") OR
         YOU CAN RESTORE ALL OF THEM FROM DOWNLOAD SOURCE. NON-TXT FILES CAN BE SAFELY REMOVED WITHOUT RESTORING. 
''')
                elif message[len(nickname)+2+10:].startswith('get'):
                    client.send(ec('SETGET'))
                    
                elif message[len(nickname)+2+10:].startswith('default'):
                    client.send(ec('SETDEF'))
                    
                elif message[len(nickname)+2+10:].startswith('load'):
                    client.send(ec('SETLOAD'))
                    
                elif message[len(nickname)+2+10:].startswith('save'):
                    client.send(ec('SETSAVE'))
                    
                elif message[len(nickname)+2+10:].startswith('erase'):
                    client.send(ec('SETDEL'))
                
                elif message[len(nickname)+2+10:].startswith('autoload'):
                    client.send(ec(f'SETALS {message[len(nickname)+2+19:]}'))

            elif message[len(nickname)+2:].startswith('/log'):
                client.send(ec(f'SRVLOG {message[len(nickname)+2+5:]}'))
            
            elif message[len(nickname)+2:].startswith('/auth'):
                client.send(ec(f'SRVATH {message[len(nickname)+2+6:]}'))

            elif message[len(nickname)+2:].startswith('/open'):
                client.send(ec(f'SRVOPN {message[len(nickname)+2+6:]}'))

            elif message[len(nickname)+2:].startswith('/users'):
                client.send(ec('USERS'))

            elif message[len(nickname)+2:].startswith('/register'):
                client.send(ec(f'REGSTR {message[len(nickname)+2+10:]}'))

            elif message[len(nickname)+2:].startswith('/deleteprofile'):
                client.send(ec(f'DELPRF {message[len(nickname)+2+15:]}'))

            elif message[len(nickname)+2:].startswith('/list'):
                client.send(ec('LIST'))

            elif message[len(nickname)+2:].startswith('/admins'):
                client.send(ec('ADMINS'))

            elif message[len(nickname)+2:].startswith('/mtlist'):
                client.send(ec('MTLIST'))

            elif message[len(nickname)+2:].startswith('/blacklist'):
                client.send(ec('BLACKLIST'))
                
            elif message[len(nickname)+2:].startswith('/dm'):
                client.send(ec(f'DM {message[len(nickname)+2+4:]}'))

            elif message[len(nickname)+2:].startswith('/op'):
                client.send(ec(f'OP {message[len(nickname)+2+4:]}'))
                
            elif message[len(nickname)+2:].startswith('/deop'):
                client.send(ec(f'DEOP {message[len(nickname)+2+6:]}'))

            elif message[len(nickname)+2:].startswith('/mute'):
                client.send(ec(f'MUTE {message[len(nickname)+2+6:]}'))

            elif message[len(nickname)+2:].startswith('/unmute'):
                client.send(ec(f'UNMUTE {message[len(nickname)+2+8:]}'))
                
            elif message[len(nickname)+2:].startswith('/kick'):
                client.send(ec(f'KICK {message[len(nickname)+2+6:]}'))
                
            elif message[len(nickname)+2:].startswith('/ban'):
                client.send(ec(f'BAN {message[len(nickname)+2+5:]}'))

            elif message[len(nickname)+2:].startswith('/unban'):
                client.send(ec(f'UNBAN {message[len(nickname)+2+7:]}'))

            elif message[len(nickname)+2:].startswith('/donut'):
                try:
                    print("Press \"ESC\" to close")
                    os.system('cmd /c "start server/donut.exe"')
                except:
                    print("No more donut for you!")
                
            elif message[len(nickname)+2:].startswith('/publicip'):
                myip = get('https://api.ipify.org').text
                print("Your public IP is: " + myip)
                
            elif message[len(nickname)+2:].startswith('/ipconfig'):
                os.system('cmd /c "ipconfig"')

            elif message[len(nickname)+2:].startswith('/ping'):
                os.system(f'cmd /c "ping {message[len(nickname)+2+6:].strip()}"')

            elif message[len(nickname)+2:].startswith('/credits'):
                print('''
Created by:                         Matteo Sinitò (MattSini912)    

Testing:                            Luca Distefano

Concept and basic TCP/IP code:      NeuralNine
Diffie-Hellman implementation:      Hyungjoon Koo
3D ASCII donut:                     codegiovanni
Original pydispo module:            Aakash Patil

''')

            elif message[len(nickname)+2:].startswith('/leave'):
                client.close()
                stop_thread = True
                continue
                
            else:
                print("Unknown command")
                
        else:
            if message[len(nickname)+2:] == "" or message[len(nickname)+2:].isspace():
                print("Message is blank")
                continue
            if len(message[len(nickname)+2:]) > 5000:
                print("Message is too long")
                continue
            client.send(ec('> ' + message))

# Starting Threads For Listening And Writing
receive_thread = threading.Thread(target=receive)
receive_thread.start()

write_thread = threading.Thread(target=write)
write_thread.start()