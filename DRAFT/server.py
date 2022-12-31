import os
import time
from socket import *
import hashlib
import base64
import random
import re
import threading
from requests import get
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from mycryptfunc import *
from pydispo import *

import traceback
import secrets
import string

app_version = "1.5.0"
compatible_versions = ["1.5.0"]
versions_list = []
try:
    url_path = 'https://raw.githubusercontent.com/MattSini912/mschat/main/MSCHAT/server/'
    versions = requests.get(url_path + 'VERSIONS')
    versions_list = versions.text.split()
    if app_version in versions_list:
        compatible_versions = versions_list[:]
        print("Version " + app_version)
    else:
        print("Version " + app_version + " - New version available!")
except:
    print("Version " + app_version)

autoload = False
dolog = True
auth = False
server_open = False

# Get timestamp
def timestamp():
    time_tuple = time.localtime()
    time_string = time.strftime("%Y/%m/%d %H:%M:%S", time_tuple)
    return ("[" + time_string + "]")

def clear_name(name):
    name = re.sub(r"[^a-zA-Z0-9 _àèìòù+&£$€@#]","",name)
    name = name.strip()
    name = name[:min(len(name), 20)]
    name = name.strip()
    name = name.replace(' ', '_')
    return name


# Server log
def log(text=""):
    global dolog
    try:
        if dolog and bool(text):
            with open('serverlog.txt','a') as f:
                f.write(f'{timestamp()} {text}\n')
    except UnicodeEncodeError:
        with open('serverlog.txt','a') as f:
                f.write(f'{timestamp()} <Unicode Error>\n')
    except:
        pass

####################################################
            
def default(option, status=False):
    ALL = False
    if option == "ALL":
        ALL = True
        
    global dolog
    if option == "dolog" or ALL:
        if status:
            return True
        dolog = True

    global auth
    if option == "auth" or ALL:
        if status:
            return True
        auth = True

    global server_open
    if option == "server_open" or ALL:
        if status:
            return False
        server_open = False

def setload():
    with open("settings.txt", "r") as f:
        lines = f.readlines()
    for line in lines:
        try:
            temp = (line.strip()).split(":",1)
            global dolog
            if temp[0] == "dolog":
                dolog = eval(temp[1])
            global auth
            if temp[0] == "auth":
                auth = eval(temp[1])
            global server_open
            if temp[0] == "server_open":
                    server_open = eval(temp[1])
        except:
            traceback.print_exc()
            continue   
   
###################################################

default("ALL")

# Start
if os.name == 'nt':
    os.system("")
    print("\033[1;34m" + "MSCHAT by MattSini912" + "\033[0m")
else:
    print("MSCHAT by MattSini912")

# Detect network
host_name = gethostname()
host_ip = gethostbyname(host_name)
print("Detected hostname:", host_name)
print("Detected private IP:", host_ip)
print(70 * "-")

auto_address = False
auto_port = False
with open("autoload.txt", "r") as f:
    log(70 * "-")
    try:
        # Load settings in settings.txt
        lines = f.readlines()
        temp = lines[0].split(":",1)
        choice = eval(temp[1].strip())
        if choice:
            autoload = True
            setload()
            print(timestamp(), 'AUTOLOAD: settings loaded from file')
            log('AUTOLOAD: settings loaded from file')

        # Load address in autoload.txt
        temp = lines[1].split(":",1)
        auto_address = temp[1].strip()
        if auto_address == "None" or auto_address == "False" or auto_address == "" or auto_address.isspace():
            auto_address = False
        if auto_address == "Auto" or auto_address == "True":
            auto_address = host_ip

        # Load address in autoload.txt
        temp = lines[2].split(":",1)
        auto_port = temp[1].strip()
        if auto_port == "None" or auto_port == "False" or auto_port == "" or auto_port.isspace():
            auto_port = False
        if auto_port == "Auto" or auto_port == "True":
            auto_port = 55555

    except:
        pass

# Connection Data
if auto_address:
    host = auto_address
    if auto_port:
        print("AUTOLOAD: detected address and port: " + auto_address + ":" + str(auto_port))
        port = int(auto_port)
    else:
        print("AUTOLOAD: detected address: " + auto_address)
        port = 55555
else:
    host = input("Enter your private IP (default = 127.0.0.1) -> ")
    port = 55555
if host == "" or host.isspace():
    host = '127.0.0.1'


# Starting Server
server = socket(AF_INET, SOCK_STREAM)
server.bind((host, port))
server.listen()
 
myip = get('https://api.ipify.org').text
print("Server started! Your public IP is: " + myip + ":" + str(port))
log("Server started! Your public IP is: " + myip + ":" + str(port))

# Lists For Clients and Their Nicknames
clients = []
nicknames = []
servers = ["SERVER"]
admins = ["SERVER", "ADMIN"]
unblocked = ["SERVER"]
muted = []
keys = []

with open("admins.txt", "r") as f:
    lines = f.readlines()
    for line in lines:
        admins.append(line.strip())

with open("unblocked.txt", "r") as f:
    lines = f.readlines()
    for line in lines:
        unblocked.append(line.strip())
        
def hashpwd(password, times=1):
    for i in range(0,times):
        h = hashlib.new('sha256')
        h.update(password.encode('utf-8', 'replace'))
        password = h.hexdigest()
    return h.hexdigest()

# Get random passwords
secureRandom = secrets.SystemRandom()
characters = string.ascii_letters + string.digits

serverpwd = ''.join(secureRandom.choice(characters) for i in range(20))
print("SERVER password is:", serverpwd)
serverpwd = hashpwd(serverpwd, 200000)

adminpwd = ''.join(secureRandom.choice(characters) for i in range(20))
print("ADMIN password is:", adminpwd)
adminpwd = hashpwd(adminpwd, 200000)

print("Type \"/settings help\" on terminal to show server's commands and settings")

# Sending Messages To All Connected Clients
def broadcast(message, clt=False):
    if bool(clt):
        try:
            if clt in clients:
                index = clients.index(clt)
                tls_key = keys[index]
                crypted = myencrypt(message, tls_key)
                clt.send(crypted.encode('utf-8', 'replace'))
        except:
            print("Error delivering a message")
    else:
        for client in clients:
            try:
                index = clients.index(client)
                tls_key = keys[index]
                crypted = myencrypt(message, tls_key)
                #print(nicknames[clients.index(client)], str(tls_key)[-10:], message[-10:], str(crypted)[-10:]) ###debug
                if client in clients:
                    client.send(crypted.encode('utf-8', 'replace'))
            except:
                print("Error delivering a message")

# Handling Messages From Clients
def handle(client, tls_key=bytes(0)):
    global admins
    global nicknames
    global muted
    global keys
    ###############################
    global autoload
    global dolog
    global auth
    global server_open
    ###############################
    message_ts = [0, 0, 0, 0, 0, 0]
    flood_count = 0
    ###############################

    def ec(string):
        if tls_key != bytes(0):
            string = myencrypt(string, tls_key)
            string = string.encode('utf-8', 'replace')
            return string
        else:
            return string.encode('utf-8', 'replace')

    def dc(token):
        if tls_key != bytes(0):
            token = mydecrypt(token, tls_key)
            return token
        else:
            return token

    def kick_user(name):
            if name in nicknames:
                name_index = nicknames.index(name)
                client_to_kick = clients[name_index]
                clients.remove(client_to_kick)
                nicknames.remove(name)
                key_to_remove = keys[name_index]
                keys.remove(key_to_remove)
                client_to_kick.send(myencrypt('KCK', key_to_remove).encode('utf-8', 'replace'))
                client_to_kick.close()
                return True
            else:
                return False

    while True:
        try:
            # Broadcasting Messages
            message = client.recv(8192)
            msg = dc(message.decode('utf-8', 'replace'))

            sender = nicknames[clients.index(client)]

            #Anti-flood filter
            new_ts = time.time()
            message_ts[0] = message_ts [1]
            message_ts[1] = message_ts [2]
            message_ts[2] = message_ts [3]
            message_ts[3] = message_ts [4]
            message_ts[4] = message_ts [5]
            message_ts[5] = new_ts
            if new_ts - message_ts[0] <= 5 and sender not in unblocked:
                flood_count += 1
                print(timestamp(), f'\"{sender}\" blocked for: flooding ({flood_count*30} s)')
                log(f'\"{sender}\" blocked for: flooding ({flood_count*30} s)')
                client.send(ec(f"Blocked for flooding! ({flood_count*30} seconds)"))
                time.sleep(flood_count*30)
                continue

            if msg.startswith('LIST'):
                userlist = f"USERS CONNECTED ({len(nicknames)}): "
                for user in nicknames:
                    userlist = userlist + user + ", "
                client.send(ec(userlist))

            elif msg.startswith('ADMINS'):
                adminlist = f"ADMINS ({len(admins)}): "
                for admin in admins:
                    adminlist = adminlist + admin + ", "
                client.send(ec(adminlist))

            elif msg.startswith('UBLIST'):
                if sender in admins:
                    botlist = f"UNBLOCKED USERS ({len(unblocked)}): "
                    for bot in unblocked:
                        botlist = botlist + bot + ", "
                    client.send(ec(botlist))
                else:
                    client.send(ec('Refused!'))
            
            elif msg.startswith('MTLIST'):
                if sender in admins:
                    mutelist = f"MUTED USERS ({len(muted)}): "
                    for mute in muted:
                        mutelist = mutelist + mute + ", "
                    client.send(ec(mutelist))
                else:
                    client.send(ec('Refused!'))

            elif msg.startswith('BLACKLIST'):
                if sender in admins:
                    with open("blacklist.txt", "r") as f:
                            lines = f.readlines()
                    blist = f"BLACKLISTED USERS ({len(lines)}): "
                    for line in lines:
                        blist = blist + line.strip() + ", "
                    client.send(ec(blist))
                else:
                    client.send(ec('Refused!'))
                    
            elif msg.startswith('DM'):
                text = msg[3:]
                if ";" not in text:
                    client.send(ec('Invalid!'))
                    continue
                textlist = text.split(";", 1)
                if len(textlist) != 2: 
                    client.send(ec('Invalid!'))
                    continue
                name_to_dm = textlist[0].strip()
                telegram = textlist[1].strip()
                if telegram == "" or telegram.isspace():
                    client.send(ec('Message blank'))
                    continue
                if name_to_dm in nicknames:
                    target_index = nicknames.index(name_to_dm)
                    client_to_dm = clients[target_index]
                    #client_to_dm.send(ec(f"(\"{sender}\" -> YOU): {telegram}"))
                    broadcast((f"(\"{sender}\" -> YOU): {telegram}"), client_to_dm)
                    client.send(ec(f"(YOU -> \"{name_to_dm}\"): {telegram}"))
                    log(f"(\"{sender}\" -> \"{name_to_dm}\"): {telegram}")
                else:
                    client.send(ec('Refused!'))

            elif msg.startswith('OP'):
                if sender in servers:
                    name_to_op = clear_name(msg[3:])
                    with open("admins.txt", "r") as f:
                        lines = f.readlines()
                    if name_to_op+'\n' not in lines and name_to_op not in admins and name_to_op!="":
                        admins.append(name_to_op)
                        with open('admins.txt','a') as f:
                            f.write(f'{name_to_op}\n')
                        print(timestamp(), f'\"{name_to_op}\" is now an admin')
                        log(f'\"{name_to_op}\" is now an admin')
                        broadcast(f'\"{name_to_op}\" is now an admin!')
                    else:
                        client.send(ec(f'\"{name_to_op}\" is already an admin'))
                else:
                    client.send(ec('Refused!'))

            elif msg.startswith('DEOP'):
                if sender in servers:
                    name_to_deop = msg[5:]
                    with open("admins.txt", "r") as f:
                        lines = f.readlines()
                    if name_to_deop+'\n' in lines and bool(lines):
                        admins.remove(name_to_deop)
                        with open("admins.txt", "w") as f:
                            for line in lines:
                                if line.strip() != name_to_deop:
                                    f.write(line)
                        print(timestamp(), f'\"{name_to_deop}\" is no more an admin')
                        log(f'\"{name_to_deop}\" is no more an admin')
                        broadcast(f'\"{name_to_deop}\" is no more an admin!')
                    else:
                        client.send(ec(f'Cannot remove \"{name_to_deop}\" as an admin'))
                else:
                    client.send(ec('Refused!'))

            elif msg.startswith('SETBOT'):
                if sender in servers:
                    name_to_bot = clear_name(msg[7:])
                    with open("unblocked.txt", "r") as f:
                        lines = f.readlines()
                    if name_to_bot+'\n' not in lines and name_to_bot not in unblocked and name_to_bot!="":
                        unblocked.append(name_to_bot)
                        with open('unblocked.txt','a') as f:
                            f.write(f'{name_to_bot}\n')
                        print(timestamp(), f'\"{name_to_bot}\" is now unblocked')
                        log(f'\"{name_to_bot}\" is now unblocked')
                        client.send(ec(f'\"{name_to_bot}\" unblocked'))
                    else:
                        client.send(ec(f'\"{name_to_bot}\" is already unblocked'))
                else:
                    client.send(ec('Refused!'))

            elif msg.startswith('DELBOT'):
                if sender in servers:
                    name_to_unbot = msg[7:]
                    with open("unblocked.txt", "r") as f:
                        lines = f.readlines()
                    if name_to_unbot+'\n' in lines and bool(lines):
                        unblocked.remove(name_to_unbot)
                        with open("unblocked.txt", "w") as f:
                            for line in lines:
                                if line.strip() != name_to_unbot:
                                    f.write(line)
                        print(timestamp(), f'\"{name_to_unbot}\" is no more unblocked')
                        log(f'\"{name_to_unbot}\" is no more unblocked')
                        client.send(ec(f'\"{name_to_unbot}\" no more unblocked'))
                    else:
                        client.send(ec(f'Cannot remove \"{name_to_unbot}\" from unblocked users'))
                else:
                    client.send(ec('Refused!'))

            elif msg.startswith('MUTE'):
                if sender in admins:
                    name_to_mute = clear_name(msg[5:])
                    if name_to_mute not in muted and name_to_mute not in admins and name_to_mute!="":
                        muted.append(name_to_mute)
                        print(timestamp(), f'\"{name_to_mute}\" muted')
                        log(f'\"{name_to_mute}\" muted')
                        broadcast(f'\"{name_to_mute}\" was muted by an admin')
                    else:
                        client.send(ec(f'Cannot mute \"{name_to_mute}\"'))
                else:
                    client.send(ec('Refused!'))

            elif msg.startswith('UNMUTE'):
                if sender in admins:
                    name_to_unmute = msg[7:]
                    if name_to_unmute in muted:
                        muted.remove(name_to_mute)
                        print(timestamp(), f'\"{name_to_unmute}\" unmuted')
                        log(f'\"{name_to_unmute}\" unmuted')
                        broadcast(f'\"{name_to_unmute}\" was unmuted by an admin')
                    else:
                        client.send(ec(f'Cannot unmute \"{name_to_unmute}\"'))
                else:
                    client.send(ec('Refused!'))

            elif msg.startswith('KICK'):
                if sender in admins:
                    name_to_kick = msg[5:]
                    if name_to_kick not in admins:
                        if kick_user(name_to_kick):
                            print(timestamp(), f'\"{name_to_kick}\" kicked')
                            log(f'\"{name_to_kick}\" kicked')
                            broadcast(f'<<< \"{name_to_kick}\" was kicked by an admin!')
                else:
                    client.send(ec('Refused!'))
                    
            elif msg.startswith('BAN'):
                if sender in admins:
                    name_to_ban = clear_name(msg[4:])
                    if name_to_ban not in admins and name_to_ban!="":
                        if kick_user(name_to_ban):
                            broadcast(f'<<< \"{name_to_ban}\" was kicked by an admin!')
                        with open('blacklist.txt','a') as f:
                            f.write(f'{name_to_ban}\n')
                        print(timestamp(), f'\"{name_to_ban}\" banned')
                        log(f'\"{name_to_ban}\" banned')
                        client.send(ec(f'\"{name_to_ban}\" banned'))
                else:
                    client.send(ec('Refused!'))

            elif msg.startswith('UNBAN'):
                if sender in admins:
                    name_to_unban = msg[6:]
                    with open("blacklist.txt", "r") as f:
                        lines = f.readlines()
                    if name_to_unban+'\n' in lines and bool(lines):
                        with open("blacklist.txt", "w") as f:
                            for line in lines:
                                if line.strip() != name_to_unban:
                                    f.write(line)
                        print(timestamp(), f'\"{name_to_unban}\" unbanned')
                        log(f'\"{name_to_unban}\" unbanned')
                        client.send(ec(f'\"{name_to_unban}\" unbanned'))
                    else:
                        client.send(ec(f'Cannot remove \"{name_to_unban}\" from blacklist'))
                else:
                    client.send(ec('Refused!'))
                    
            #############################################################
                    
            elif msg.startswith('SETGET'):
                if sender in servers:
                    client.send(ec(f'''

SERVER SETTINGS:

autoload: {str(autoload).lower()}

log: {str(dolog).lower()}
auth: {str(auth).lower()}
open: {str(server_open).lower()}

'''))
                else:
                    client.send(ec('Refused!'))

            elif msg.startswith('SETDEF'):
                if sender in servers:
                    default("ALL")
                    print(timestamp(), 'Settings restored to default')
                    log('Settings restored to default')
                    client.send(ec('Done!'))
                else:
                    client.send(ec('Refused!'))

            elif msg.startswith('SETLOAD'):
                if sender in servers:
                    setload()
                    print(timestamp(), 'Settings loaded from file')
                    log('Settings loaded from file')
                    client.send(ec('Done!'))
                else:
                    client.send(ec('Refused!'))

            elif msg.startswith('SETSAVE'):
                if sender in servers:
                    with open('settings.txt','w') as f:
                        f.write(f'dolog:{dolog}\n')
                        f.write(f'auth:{auth}\n')
                        f.write(f'server_open:{server_open}\n')
                    print(timestamp(), 'Settings saved on file')
                    log('Settings saved on file')
                    client.send(ec('Done!'))
                else:
                    client.send(ec('Refused!'))

            elif msg.startswith('SETDEL'):
                if sender in servers:
                    with open('settings.txt','w') as f:
                        f.write(f'dolog:{default("dolog",True)}\n')
                        f.write(f'auth:{default("auth",True)}\n')
                        f.write(f'server_open:{default("server_open",True)}\n')
                    print(timestamp(), 'Settings deleted from file')
                    log('Settings deleted from file')
                    client.send(ec('Done!'))
                else:
                    client.send(ec('Refused!'))

            elif msg.startswith('SETALS'):
                if sender in servers:
                    choice = msg[7:]
                    if choice.lower() == "true":
                        autoload = True
                    else:
                        autoload = False
                    with open('autoload.txt','w') as f:
                            f.write(f'autoload:{autoload}\n')
                            f.write(f'address:None\n')
                    print(timestamp(), f'Setting "autoload" to {autoload}')
                    log(f'Setting "autoload" to {autoload}')
                    client.send(ec(f'Set to {autoload}'))
                else:
                    client.send(ec('Refused!'))

            elif msg.startswith('SRVLOG'):
                if sender in servers:
                    choice = msg[7:]
                    if choice.lower() == "true":
                        dolog = True
                    elif choice.lower() == "false":
                        log('Setting "log" to False')
                        dolog = False
                    else:
                        default("dolog")
                    print(timestamp(), f'Setting "log" to {dolog}')
                    log(f'Setting "log" to {dolog}')
                    client.send(ec(f'Set to {dolog}'))
                else:
                    client.send(ec('Refused!'))

            elif msg.startswith('SRVATH'):
                if sender in servers:
                    choice = msg[7:]
                    if choice.lower() == "true":
                        auth = True
                    elif choice.lower() == "false":
                        auth = False
                    else:
                        default("auth")
                    print(timestamp(), f'Setting "auth" to {auth}')
                    log(f'Setting "auth" to {auth}')
                    client.send(ec(f'Set to {auth}'))
                else:
                    client.send(ec('Refused!'))

            elif msg.startswith('SRVOPN'):
                if sender in servers:
                    choice = msg[7:]
                    if choice.lower() == "true":
                        server_open = True
                    elif choice.lower() == "false":
                        server_open = False
                    else:
                        default("server_open")
                    print(timestamp(), f'Setting "open" to {server_open}')
                    log(f'Setting "open" to {server_open}')
                    client.send(ec(f'Set to {server_open}'))
                else:
                    client.send(ec('Refused!'))

            elif msg.startswith('USERS'):
                if sender in servers:
                    with open("login_details.txt", "r") as f:
                        lines = f.readlines()
                    registeredlist = f"USERS REGISTERED ({len(lines)}): "
                    for line in lines:
                        details = line.split(":", 2)
                        registered = f'{details[0].strip()} ({details[1].strip()})'
                        registeredlist = registeredlist + registered + ", "                            
                    client.send(ec(registeredlist))
                else:
                    client.send(ec('Refused!'))
            
            elif msg.startswith('REGSTR'):
                if sender in servers:
                    text = msg[7:]
                    if ";" not in text:
                        client.send(ec('Invalid!'))
                        continue
                    textlist = text.split(";", 1)
                    if len(textlist) != 2: 
                        client.send(ec('Invalid!'))
                        continue
                    name_to_reg = textlist[0].strip()
                    pwd_to_reg = textlist[1].strip()

                    name_to_reg = clear_name(name_to_reg)
                    if name_to_reg == "" or name_to_reg.isspace() or name_to_reg == ":":
                        client.send(ec('Invalid!'))
                        continue

                    if pwd_to_reg == "" or pwd_to_reg.isspace() or pwd_to_reg == ":" or len(pwd_to_reg) < 4  or len(pwd_to_reg) > 20:
                        client.send(ec('Invalid!'))
                        continue                
                    pwd_to_reg = hashpwd(pwd_to_reg, 200000)

                    test=False
                    with open("login_details.txt", "r") as f:
                        lines = f.readlines()
                        for line in lines:
                            if name_to_reg+':' in line:
                                test=True
                    if test:
                        client.send(ec('Already registered!'))
                        continue
                    with open('login_details.txt','a') as f:
                        f.write(f'{name_to_reg}:NONE:{pwd_to_reg}\n')
                    print(timestamp(), f'User \"{name_to_reg}\" registered from console')
                    log(f'User \"{name_to_reg}\" registered from console')
                    client.send(ec(f'User \"{name_to_reg}\" registered'))

                else:
                    client.send(ec('Refused!'))

            elif msg.startswith('DELPRF'):
                if sender in servers:
                    name_to_del = msg[7:].strip()
                    test=False
                    with open("login_details.txt", "r") as f:
                        lines = f.readlines()
                        for line in lines:
                            if name_to_del+':' in line:
                                test=True
                    if test:
                        with open("login_details.txt", "w") as f:
                            for line in lines:
                                if not name_to_del+':' in line:
                                    f.write(line)
                        print(timestamp(), f'User \"{name_to_del}\" deleted from console')
                        log(f'User \"{name_to_del}\" deleted from console')
                        client.send(ec(f'User \"{name_to_del}\" deleted'))
                    else:
                        client.send(ec('Refused!'))
                else:
                    client.send(ec('Refused!'))
            #################################################################
                    
            else:
                if sender in muted:
                    client.send(ec('You are muted!'))
                else:
                    if ":" in msg:
                        msglist = msg.split(":", 1)
                        name_to_test = msglist[0].replace(">", "").strip()
                        if name_to_test == sender:
                            broadcast(msg)
                            log(msg)
                        else:
                            name_to_kick = sender
                            print(timestamp(), f'\"{name_to_kick}\" tried to send a message with a different nickname')
                            log(f'\"{name_to_kick}\" tried to send a message with a different nickname')
                            client.send(ec('Message refused!'))
                            if kick_user(name_to_kick):
                                print(timestamp(), f'\"{name_to_kick}\" kicked for: sending an altered message')
                                log(f'\"{name_to_kick}\" kicked for: sending an altered message')
                                broadcast(f'<<< \"{name_to_kick}\" was kicked!')
                    else:
                        client.send(ec('Invalid message!'))
        except Exception as exc:
            # Removing And Closing Clients
            if client in clients:
                if bool(exc):
                    print(exc)
                else:
                    traceback.print_exc()
                index = clients.index(client)
                clients.remove(client)
                client.close()
                nickname = nicknames[index]
                print(timestamp(), f'\"{nickname}\" disconnected')
                log(f'\"{nickname}\" disconnected')
                broadcast(f'<<< \"{nickname}\" left!')
                nicknames.remove(nickname)
                tls_key = keys[index]
                keys.remove(tls_key)
                break
    
# Receiving / Listening Function
def receive():
    global auth
    global server_open
    global keys
    tls_key = bytes(0)

    def ec(string):
        if tls_key != bytes(0):
            string = myencrypt(string, tls_key)
            string = string.encode('utf-8', 'replace')
            return string
        else:
            return string.encode('utf-8', 'replace')

    def dc(token):
        if tls_key != bytes(0):
            token = mydecrypt(token, tls_key)
            return token
        else:
            return token

    while True:
        try:
            # Accept Connection
            client, address = server.accept()
            print(timestamp(), "Connected with {}".format(str(address)))
            log("Connected with {}".format(str(address)))

            client.send('ASKVER'.encode('utf-8', 'replace'))
            client_version = client.recv(1024).decode('utf-8', 'replace')
            if client_version not in compatible_versions:
                client.send(('OLDVER').encode('utf-8', 'replace'))
                client.close()
                print(timestamp(), f'Refused {str(address)}: incompatible version ({client_version})')
                log(f'Refused {str(address)}: incompatible version ({client_version})')
                continue
            
            client.send('CLTKEY'.encode('utf-8', 'replace'))
            clt_key = client.recv(2048).decode('utf-8', 'replace')
            request = client.recv(1024).decode('utf-8', 'replace')
            if request == 'SRVKEY':
                srv = DiffieHellman()
                client.send(str(srv.publicKey).encode('utf-8', 'replace'))
                srv.generateKey(int(clt_key))
                tls_key = srv.getKey()

                if tls_key != bytes(0):
                    dig = hashlib.sha256(bytes(str(srv.publicKey).encode('utf-8', 'replace')))
                    salt = bytes(dig.digest()[:32])
                    kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA512(),
                    length=32,
                    salt=salt,
                    iterations=350000,
                    )
                    tls_key = base64.urlsafe_b64encode(kdf.derive(tls_key))

                    # Validate encryption
                    verrequest = client.recv(1024).decode('utf-8', 'replace')
                    if verrequest == 'VERTLS':
                        secureRandom = secrets.SystemRandom()
                        characters = string.digits
                        vercode = int(''.join(secureRandom.choice(characters) for i in range(6)))
                        client.send(ec(str(vercode)))
                        vercode *= vercode
                        clt_response = dc(client.recv(1024).decode('utf-8', 'replace'))
                        if clt_response == str(vercode):
                            print(timestamp(), f'Encrypted tunnel established with {str(address)}')
                            log(f'Encrypted tunnel established with {str(address)}')
                            client.send('Encrypted tunnel active!'.encode('utf-8', 'replace'))
                        else:
                            print(timestamp(), f'Failed to create an encrypted tunnel with {str(address)}')
                            log(f'Failed to create an encrypted tunnel with {str(address)}')
                            client.send('Failed to create an encrypted tunnel!'.encode('utf-8', 'replace'))
                    else:
                        client.send(ec('REFUSE'))
                        client.close()
                        print(timestamp(), f'Refused {str(address)}: invalid request')
                        log(f'Refused {str(address)}: invalid request')
                        continue
 
            client.send(ec('CMD'))
            command = dc(client.recv(1024).decode('utf-8', 'replace'))
            
            def otp (client, email):
                email_addr = generate_email_address(size=10)
                secureRandom = secrets.SystemRandom()
                characters = string.digits
                otpcode = ''.join(secureRandom.choice(characters) for i in range(6))
                client.send(ec(f'Within 5 minutes send an email at: {email_addr} with this code as subject: {otpcode} and wait'))

                d = dict()
                tries = 0
                while(not bool(d) and tries < 30):
                    time.sleep(10)
                    d = check_mailbox(email_addr,showInbox=False,showRecent=True)
                    tries += 1
                if not bool(d):
                    return False
                
                if d["from"] == email and otpcode == d["subject"].strip():
                    return True
                else:
                    return False

            if command.startswith('REGISTER'):
                try:
                    if not (auth and server_open):
                        client.send(ec('CLOSED'))
                        client.close()
                        print(timestamp(), f'Refused {str(address)}: users are not able to register at the moment')
                        log(f'Refused {str(address)}: users are not able to register at the moment')
                        continue
                    print(timestamp(), f'Pending {str(address)}: user is trying to register')
                    log(f'Pending {str(address)}: user is trying to register')
                    text = command[9:]
                    if ";" not in text:
                        client.send(ec('REFUSE'))
                        client.close()
                        print(timestamp(), f'Refused {str(address)}: invalid request')
                        log(f'Refused {str(address)}: invalid request')
                        continue
                    textlist = text.split(";", 2)
                    if len(textlist) != 3: 
                        client.send(ec('REFUSE'))
                        client.close()
                        print(timestamp(), f'Refused {str(address)}: invalid request')
                        log(f'Refused {str(address)}: invalid request')
                        continue
                    name_to_reg = textlist[0].strip()
                    mail_to_reg = textlist[1].strip()
                    pwd_to_reg = textlist[2].strip()
                    pwd_to_reg = hashpwd(pwd_to_reg, 100000)

                    name_to_reg = clear_name(name_to_reg)
                    if name_to_reg == "" or name_to_reg.isspace() or name_to_reg == ":":
                        client.send(ec('REFUSE'))
                        client.close()
                        print(timestamp(), f'Refused {str(address)}: invalid request')
                        log(f'Refused {str(address)}: invalid request')
                        continue

                    mail_to_reg = re.sub(r"[^a-zA-Z0-9_~+@\.\-]","",mail_to_reg).strip()              
                    
                    test=False
                    with open("login_details.txt", "r") as f:
                        lines = f.readlines()
                        for line in lines:
                            if name_to_reg+':' in line or ':'+mail_to_reg+':' in line:
                                test=True
                    if test or name_to_reg == "SERVER" or name_to_reg == "ADMIN":
                        client.send(ec('DOUBLE'))
                        client.close()
                        print(timestamp(), f'Refused {str(address)}: name already registered')
                        log(f'Refused {str(address)}: name already registered')
                        continue
                
                    if otp(client,mail_to_reg):
                        with open('login_details.txt','a') as f:
                            f.write(f'{name_to_reg}:{mail_to_reg}:{pwd_to_reg}\n')
                        print(timestamp(), f'User \"{name_to_reg}\" registered from client {str(address)}')
                        log(f'User \"{name_to_reg}\" registered from client {str(address)}')
                        client.send(ec(f'User \"{name_to_reg}\" registered'))
                        client.send(ec('DONE'))
                        client.close() 
                        continue

                    else:
                        client.send(ec('REFUSE'))
                        client.close()
                        print(timestamp(), f'Refused {str(address)}: failed to authenticate')
                        log(f'Refused {str(address)}: failed to authenticate')
                        continue

                except:
                    traceback.print_exc()
                    client.send(ec('CLOSED'))
                    client.close()
                    print(timestamp(), f'Refused {str(address)}: error')
                    log(f'Refused {str(address)}: error')
                    continue


            if command.startswith('DELETE'):
                try:
                    if not (auth and server_open):
                        client.send(ec('CLOSED'))
                        client.close()
                        print(timestamp(), f'Refused {str(address)}: users are not able to delete accounts at the moment')
                        log(f'Refused {str(address)}: users are not able to delete accounts at the moment')
                        continue
                    print(timestamp(), f'Pending {str(address)}: user is trying to delete account')
                    log(f'Pending {str(address)}: user is trying to delete account')
                    mail_to_del = command[7:].strip()
                    if mail_to_del == "" or mail_to_del.isspace() or mail_to_del == ":" or mail_to_del == "NONE":
                        client.send(ec('REFUSE'))
                        client.close()
                        print(timestamp(), f'Refused {str(address)}: invalid request')
                        log(f'Refused {str(address)}: invalid request')
                        continue
                    mail_to_del = re.sub(r"[^a-zA-Z0-9_~+@\.\-]","",mail_to_del).strip()              
                    
                    test=False
                    with open("login_details.txt", "r") as f:
                        lines = f.readlines()
                        for line in lines:
                            if ':'+mail_to_del+':' in line:
                                test=True
                    if not test:
                        client.send(ec('REFUSE'))
                        client.close()
                        print(timestamp(), f'Refused {str(address)}: invalid request')
                        log(f'Refused {str(address)}: invalid request')
                        continue
                    
                    name_to_del = mail_to_del
                    if otp(client,mail_to_del):
                        with open('login_details.txt','r') as f:
                            lines = f.readlines()
                        with open("login_details.txt", "w") as f:
                            for line in lines:
                                if not ':'+mail_to_del+':' in line:
                                    f.write(line)
                                else:
                                    name_to_del = (line.split(":", 2)[0]).strip()

                        print(timestamp(), f'User \"{name_to_del}\" deleted from client {str(address)}')
                        log(f'User \"{name_to_del}\" deleted from client {str(address)}')
                        client.send(ec(f'User \"{name_to_del}\" deleted'))
                        client.send(ec('DONE'))
                        client.close() 
                        continue

                    else:
                        client.send(ec('REFUSE'))
                        client.close()
                        print(timestamp(), f'Refused {str(address)}: failed to authenticate')
                        log(f'Refused {str(address)}: failed to authenticate')
                        continue

                except:
                    traceback.print_exc()
                    client.send(ec('CLOSED'))
                    client.close()
                    print(timestamp(), f'Refused {str(address)}: error')
                    log(f'Refused {str(address)}: error')
                    continue

            # Request And Store Nickname
            client.send(ec('NICK'))
            nickname = dc(client.recv(1024).decode('utf-8', 'replace'))
            
            # Clean nickname
            nickname = clear_name(nickname)
            if nickname == "" or nickname.isspace() or nickname == ":":
                nickname = str(random.randint(10000, 99999))

            with open('blacklist.txt','r') as f:
                banlist = f.readlines()
            
            if nickname+'\n' in banlist:
                client.send(ec('BAN'))
                print(timestamp(), f"Refused {str(address)}: user \"{nickname}\" is banned")
                log(f"Refused {str(address)}: user \"{nickname}\" is banned")
                client.close()
                continue

            if nickname in nicknames:
                client.send(ec('DOUBLE'))
                print(timestamp(), f"Refused {str(address)}: user \"{nickname}\" is already in the chat")
                log(f"Refused {str(address)}: user \"{nickname}\" is already in the chat")
                client.close()
                continue

            if not server_open and nickname != "SERVER" and nickname != "ADMIN":
                client.send(ec('CLOSED'))
                print(timestamp(), f"Refused {str(address)}: user \"{nickname}\" can't join because the server is closed")
                log(f"Refused {str(address)}: user \"{nickname}\" can't join because the server is closed")
                client.close()
                continue

            if nickname == "SERVER" or nickname == "ADMIN" or auth:
                client.send(ec('PASS'))
                password = dc(client.recv(1024).decode('utf-8', 'replace'))
                password = hashpwd(password, 100000)

                if (nickname == "SERVER" and password != serverpwd) or (nickname == "ADMIN" and password != adminpwd):
                    client.send(ec('REFUSE'))
                    print(timestamp(), f"Refused {str(address)}: user \"{nickname}\" entered wrong password")
                    log(f"Refused {str(address)}: user \"{nickname}\" entered wrong password")
                    client.close()
                    continue

                if (nickname != "SERVER" and nickname != "ADMIN"):
                    test=False
                    with open("login_details.txt", "r") as f:
                        lines = f.readlines()
                        for line in lines:
                            if nickname+':' in line:
                                if (line.split(":", 2))[2].strip() == password:
                                    test=True
                    if not test:
                        client.send(ec('REFUSE'))
                        print(timestamp(), f"Refused {str(address)}: user \"{nickname}\" entered wrong nickname or password")
                        log(f"Refused {str(address)}: user \"{nickname}\" entered wrong nickname or password")
                        client.close()
                        continue


            client.send(ec('CONNECTED'))

            nicknames.append(nickname)
            clients.append(client)
            keys.append(tls_key)

            time.sleep(1)

            # Print And Broadcast Nickname
            print(timestamp(), f"Accepted {str(address)}: user \"{nickname}\" joined")
            log(f"Accepted {str(address)}: user \"{nickname}\" joined")
            broadcast(f">>> \"{nickname}\" joined!")
            client.send(ec(f'Connected to server as \"{nickname}\"! {len(nicknames)} users online. List of commands: /help'))

            # Start Handling Thread For Client
            thread = threading.Thread(target=handle, args=(client, tls_key,))
            thread.start()

        except:
            # Removing And Closing Clients
            if client in clients:
                traceback.print_exc()
                index = clients.index(client)
                clients.remove(client)
                client.close()
                nickname = nicknames[index]
                print(timestamp(), f'\"{nickname}\" disconnected')
                log(f'\"{nickname}\" disconnected')
                broadcast(f'<<< \"{nickname}\" left!')
                nicknames.remove(nickname)
                tls_key = keys[index]
                keys.remove(tls_key)
                break
        
print("Server is listening...")
print()
receive()
