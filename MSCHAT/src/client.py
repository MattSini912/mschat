import os
import shutil
import requests
import urllib.request
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

import subprocess
from mycryptfunc import *
from mydonut import *

import PySimpleGUI as sg
from queue import Queue

import pywintypes
import win32con
import win32gui

client_version = "1.5.1" #<---------------------------------

os.system('cls')

_r = "\033[1;31m" #red
_g = "\033[1;32m" #green
_b = "\033[1;34m" #blue
_w = "\033[1;37m" #white
_bkw = "\033[30;107m" #black on white
_e = "\033[0m" #end

def random_logo():
    logo = 0

    if os.name == 'nt':
        logo = random.randint(0,5)
    else:
        print("MSCHAT by MattSini912")
        return

    _ms, _ch, _at = _w, _w, _w
    if logo == 1:
        _ms, _ch, _at = _b, _b, _b
    elif logo == 2:
        _ms, _ch, _at = _g, _w, _r
    elif logo == 3:
        _ms, _ch, _at = _r, _r, _r
    elif logo == 4:
        _ms, _ch, _at = _g, _g, _g
    elif logo == 5:
        _ms, _ch, _at = _bkw, _bkw, _bkw

    print(_ms + "                " + _e + _ch + "     _     " + _e + _at + "      _    " + _e)
    print(_ms + "  _ __ ___  ___ " + _e + _ch + " ___| |__  " + _e + _at + " __ _| |_  " + _e)
    print(_ms + " | '_ ` _ \/ __|" + _e + _ch + "/ __| '_ \ " + _e + _at + "/ _` | __| " + _e)
    print(_ms + " | | | | | \__ \\"+ _e + _ch + " (__| | | |" + _e + _at + " (_| | |_  " + _e)
    print(_ms + " |_| |_| |_|___/" + _e + _ch + "\___|_| |_|" + _e + _at + "\__,_|\__| " + _e)
    print(_ms + "                " + _e + _ch + "           " + _e + _at + "           " + _e)
    print(f"                {client_version}")
    print()
    print(" https://github.com/MattSini912/mschat")
    print(" " + 37*"_")

#Flash window
cur_window = None
def flash(hwnd):
        win32gui.FlashWindowEx(hwnd, win32con.FLASHW_ALL | win32con.FLASHW_TIMERNOFG, 0, 0)

import traceback ###debug

servers = ["SERVER"]
admins = ["ADMIN", "SERVER"]

enable_gui = True

# Start
if os.name == 'nt':
    os.system("")
 
random_logo()

def hashpwd(password, times=1, salt=""):
    if salt != "":
        password = salt + "$" + password
    for i in range(0,times):
        h = hashlib.new('sha256')
        h.update(password.encode('utf-8', 'replace'))
        password = h.hexdigest()
    return h.hexdigest()

def clear_name(name):
    name = re.sub(r"[^a-zA-Z0-9 _àèìòù+&£$€@#]","",name)
    name = name.strip()
    name = name[:min(len(name), 20)]
    name = name.strip()
    name = name.replace(' ', '_')
    return name

mode = input('''
Type one of the folowing options:

 /login         (DEFAULT, connect to a server)
 /register      (register to a server that uses authentication)
 /delete        (delete your profile from a server)
 /nogui         (login mode without GUI, you'll use this terminal to chat)
 /restore       (delete 'server' folder and download it again from GitHub)

---> ''').lower()

if "restore" not in mode:
    hostip = input("Enter server's IP address (default = 127.0.0.1) -> ")
    if hostip == "" or hostip.isspace():
        hostip = '127.0.0.1'

    port = input("Enter server's port (default = 55555) -> ")
    if port == "" or port.isspace():
        port = 55555

if "login" in mode:
    operation = 'LOGIN'
    command = 'LOGIN'

elif "register" in mode:
    enable_gui = False
    operation = 'REGISTER'
    name_to_reg = input("Choose a nickname -> ")
    name_to_reg = clear_name(name_to_reg)
    if name_to_reg == "" or name_to_reg.isspace() or name_to_reg == ": ":
        name_to_reg = "user" + str(random.randint(10000, 99999))

    mail_to_reg = input("Email -> ")
    mail_to_reg = re.sub(r"[^a-zA-Z0-9_~+@\.\-]","",mail_to_reg).strip()

    pwd_to_reg = input("Password -> ")
    pwd_to_reg = hashpwd(pwd_to_reg, 100000, name_to_reg)

    command = f'REGISTER {name_to_reg};{mail_to_reg};{pwd_to_reg}'

elif "delete" in mode:
    enable_gui = False
    operation = 'DELETE'
    mail_to_del = input("Email -> ")
    mail_to_del = re.sub(r"[^a-zA-Z0-9_~+@\.\-]","",mail_to_del).strip()
    command = f'DELETE {mail_to_del}'

elif "nogui" in mode:
    enable_gui = False
    operation = 'LOGIN'
    command = 'LOGIN'

elif "restore" in mode:
    folder_path = os.getcwd() + "\server"
    if os.path.exists(folder_path):
        print("\nClose all the files and executables from 'server' folder!\nDeletion will start in 15 seconds.")
        time.sleep(15)
        input("Press ENTER to start -> ")
        print("Deleting... Do not close this window!")
        for filename in os.listdir(folder_path):
            file_path = os.path.join(folder_path, filename)
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
            except Exception as e:
                print('Failed to delete %s. Reason: %s' % (file_path, e))
        #os.rmdir(folder_path)
        print("Files deleted!")
    else:
        os.mkdir(folder_path)
        print("Folder 'server' not found in the directory, a new one was created.")


    url_path = 'https://raw.githubusercontent.com/MattSini912/mschat/main/MSCHAT/server/'
    print("Downloading files from " + url_path)
    files = requests.get(url_path + 'FILES')
    filelist = files.text.split()
    for filename in filelist:
        print("Downloading " + filename)
        f = urllib.request.urlopen(url_path + filename)
        file = f.read()
        f.close()
        if filename.endswith('.exe'):
            f2 = open(folder_path + "\ "[0] + filename, 'wb')
            f2.write(file)
        else:
            f2 = open(folder_path + "\ "[0] + filename, 'w')
            f2.write(str(file.decode('utf-8')).replace('\r',''))
        f2.close()

    input("Operation terminated!")
    exit()
    

else:
    operation = 'LOGIN'
    command = 'LOGIN'


if operation == 'LOGIN':
    nickname = input("Your nickname -> ")
elif operation in ("REGISTER", "DELETE"):
    nickname = "user"
else:
    nickname = "isarandomnick"

# Clean nickname
nickname = clear_name(nickname)
if nickname == "" or nickname.isspace() or nickname == ": ":
    nickname = str(random.randint(10000, 99999))

if operation == 'LOGIN':
    password = input("- NOTE: some servers or profiles may require a password to connect, leave blank if it's not your case.\nPassword for profile -> ")
else:
    password = "isarandompass"

password = hashpwd(password, 100000, nickname)

# Connecting To Server
print()
print("Connecting...")
client = socket(AF_INET, SOCK_STREAM)
client.connect((hostip, int(port)))
print("Making requests...")

stop_thread = False
tls_key = bytes(0)
window = None

# Get timestamp
def timestamp():
    time_tuple = time.localtime()
    time_string = time.strftime("%Y/%m/%d %H:%M:%S", time_tuple)
    return ("[" + time_string + "]")

def ec(string):
    global tls_key
    if tls_key != bytes(0):
        string = myencrypt(string, tls_key)
        string = string.encode('utf-8', 'replace')
        return string
    else:
        return string.encode('utf-8', 'replace')

def dc(token):
    global tls_key
    if tls_key != bytes(0):
        token = mydecrypt(token, tls_key)
        return token
    else:
        return token

def defprint(txt=""):
    if window and enable_gui:
        window.write_event_value('-PRINT-', txt)
        return
    print(txt)
    return

# Listening to Server and Sending Nickname
def receive():
    while True:
        global stop_thread
        global tls_key
        global window
        if stop_thread:
            break
        try:
            # Receive Message From Server
            message = client.recv(8192).decode('utf-8', 'replace')
            try: 
                message = dc(message)
            except: ###debug
                defprint("Error while receiving a message") ###debug
                continue
    
            if message == 'CLTKEY':
                clt = DiffieHellman()
                client.send(str(clt.publicKey).encode('utf-8', 'replace'))
                client.send('SRVKEY'.encode('utf-8', 'replace'))
                srv_key = client.recv(2048).decode('utf-8', 'replace')
                clt.generateKey(int(srv_key))
                tls_key = clt.getKey()

                if tls_key != bytes(0):
                    dig = hashlib.sha256(bytes(str(srv_key).encode('utf-8', 'replace')))
                    salt = bytes(dig.digest()[:32])
                    kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA512(),
                    length=32,
                    salt=salt,
                    iterations=350000,
                    )
                    tls_key = base64.urlsafe_b64encode(kdf.derive(tls_key))

                    # Validate encryption
                    client.send('VERTLS'.encode('utf-8', 'replace'))
                    vercode = int(dc(client.recv(1024).decode('utf-8', 'replace')))
                    vercode *= vercode
                    client.send(ec(str(vercode)))
                    response = client.recv(1024).decode('utf-8', 'replace')
                    print(response)
                    print()

            elif message == 'CONNECTED':

                if enable_gui:
                    mygui_thread.start() #open the GUI

                    if cur_window and os.name == 'nt' and win32gui.GetForegroundWindow() != cur_window:
                        flash(cur_window)
                        
            elif message == 'ASKVER':
                client.send(client_version.encode('utf-8', 'replace'))
            
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

            elif message == 'OLDVER':
                print("This server is using a different version!")
                client.close()
                stop_thread = True
            
            elif message == 'DOUBLE':
                print("Another user with your data is already present!")
                client.close()
                stop_thread = True

            elif message == 'KCK':
                print("Kicked from the server!")
                client.close()
                if window:
                    window.close()
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
                    defprint(f"{timestamp()} {message}")
                    try:
                        if cur_window and os.name == 'nt' and win32gui.GetForegroundWindow() != cur_window:
                            flash(cur_window)
                    except:
                        pass

        except:
            traceback.print_exc() ###debug
            # Close Connection When Error
            print("An error occured!")
            client.close()
            break
        
def write(txtbox):
    global stop_thread
    global tls_key
    while True:
        if stop_thread:
            break
        try:
            if enable_gui:
                gui_text = str(txtbox.get()) # Get text from GUI, replace with input() to use console
                message = '{}: {}'.format(nickname, gui_text)
            else:
                message = '{}: {}'.format(nickname, input())
        except:
            defprint("Message not delivered")
        skip = len(nickname)+2
        if message[skip:].startswith('/'):
            
            if message[skip:].startswith('/help'):
                defprint('''
LIST OF COMMANDS:              |PERMISS.|DESCRIPTION                 
/source                         (client) Open the GitHub page of this project
/help                           (client) Print the list of commands
/settings help                  (server) Print the list of server's commands and settings
/list                           (client) Print the list of online users
/admins                         (client) Print the list of admins
/bots                           (admins) Print the list of unblocked users
/mtlist                         (admins) Print the list of muted users
/blacklist                      (admins) Print the list of banned users
/dm <user>; <message>           (client) Send <message> only to <user> 
/op <user>                      (server) Gives <user> admin's permissions
/deop <user>                    (server) Remove <user> admin's permissions
/setbot <user>                  (server) Prevent <user> from being blocked (useful for bots)
/delbot <user>                  (server) Revert /setbot
/mute <user>                    (admins) Mute <user>
/unmute <user>                  (admins) Unmute <user>
/kick <user>                    (admins) Disconnect <user>
/ban <user>                     (admins) Ban <user>
/unban <user>                   (admins) Unban <user>
/donut                          (donuts) It's a donut!
/publicip                       (client) Print your IP address
/ipconfig                       (client) Open terminal and run /ipconfig
/ping <address>                 (client) Get latency beetween your pc and <address>
/credits                        (client) Show credits page
/clear                          (client) Clear terminal
/leave                          (client) Disconnect yourself

''')
            elif message[skip:].startswith('/source'):
                try:
                    if os.name == 'nt':
                        os.system('cmd /c "start https://github.com/MattSini912/mschat"')
                except:
                    defprint("¯\(°_o)/¯")
            
            elif message[skip:].startswith('/settings'):
                if nickname not in servers:
                    defprint(f"{timestamp()} Refused!")
                    continue
                
                if message[skip+10:].startswith('help'):
                    defprint('''
LIST OF COMMANDS:              |PERMISS.|DEFAULT|DESCRIPTION                 
/settings help                  (server)         Print the list of server's commands and settings
/settings get                   (server)         Print current configuration of the settings
/settings default               (server)         Set all settings to their default configuration
/settings load                  (server)         Load the settings stored in settings.txt
/settings save                  (server)         Save the current settings in settings.txt   
/settings erase                 (server)         Erase saved settings in settings.txt
/settings autoload [true/false] (server)  false  Run "/settings load" when starting the server
/log [true/false/default]       (server)  true   Enable server log
/auth [true/false/default]      (server)  false  Force user's authentication
/open [true/false/default]      (server)  true   Let users (other than SERVER and ADMIN) connect to your server
/flood [true/false/default]     (server)  true   Block users that flood the chat with messages
/users                          (server)         Print the list of registered users
/register <user>; <password>    (server)         Register a user without authentication using <user> and <password>
/deleteprofile <user>           (server)         Delete <user> without authentication

WARNING! EDITING OR DELETING FILES FROM "SERVER" FOLDER (e.g. "login_details.txt") COULD CAUSE A SERVER MALFUNCTION,
         IF YOU HAVE PROBLEMS TRY TO DELETE THE CONTENTS OF TEXT FILES (EXCEPT "autoload.txt" AND "settings.txt") OR
         YOU CAN RESTORE ALL OF THEM FROM DOWNLOAD SOURCE. NON-TXT FILES CAN BE SAFELY REMOVED WITHOUT RESTORING. 
''')
                elif message[skip+10:].startswith('get'):
                    client.send(ec('SETGET'))
                    
                elif message[skip+10:].startswith('default'):
                    client.send(ec('SETDEF'))
                    
                elif message[skip+10:].startswith('load'):
                    client.send(ec('SETLOAD'))
                    
                elif message[skip+10:].startswith('save'):
                    client.send(ec('SETSAVE'))
                    
                elif message[skip+10:].startswith('erase'):
                    client.send(ec('SETDEL'))
                
                elif message[skip+10:].startswith('autoload'):
                    client.send(ec(f'SETALS {message[skip+19:]}'))

            elif message[skip:].startswith('/log'):
                client.send(ec(f'SRVLOG {message[skip+5:]}'))
            
            elif message[skip:].startswith('/auth'):
                client.send(ec(f'SRVATH {message[skip+6:]}'))

            elif message[skip:].startswith('/open'):
                client.send(ec(f'SRVOPN {message[skip+6:]}'))

            elif message[skip:].startswith('/flood'):
                client.send(ec(f'SRVFLD {message[skip+7:]}'))

            elif message[skip:].startswith('/users'):
                client.send(ec('USERS'))

            elif message[skip:].startswith('/register'):
                client.send(ec(f'REGSTR {message[skip+10:]}'))

            elif message[skip:].startswith('/deleteprofile'):
                client.send(ec(f'DELPRF {message[skip+15:]}'))

            elif message[skip:].startswith('/list'):
                client.send(ec('LIST'))

            elif message[skip:].startswith('/admins'):
                client.send(ec('ADMINS'))

            elif message[skip:].startswith('/bots'):
                client.send(ec('UBLIST'))

            elif message[skip:].startswith('/mtlist'):
                client.send(ec('MTLIST'))

            elif message[skip:].startswith('/blacklist'):
                client.send(ec('BLACKLIST'))
                
            elif message[skip:].startswith('/dm'):
                client.send(ec(f'DM {message[skip+4:]}'))

            elif message[skip:].startswith('/op'):
                client.send(ec(f'OP {message[skip+4:]}'))
                
            elif message[skip:].startswith('/deop'):
                client.send(ec(f'DEOP {message[skip+6:]}'))
            
            elif message[skip:].startswith('/setbot'):
                client.send(ec(f'SETBOT {message[skip+8:]}'))

            elif message[skip:].startswith('/delbot'):
                client.send(ec(f'DELBOT {message[skip+8:]}'))

            elif message[skip:].startswith('/mute'):
                client.send(ec(f'MUTE {message[skip+6:]}'))

            elif message[skip:].startswith('/unmute'):
                client.send(ec(f'UNMUTE {message[skip+8:]}'))
                
            elif message[skip:].startswith('/kick'):
                client.send(ec(f'KICK {message[skip+6:]}'))
                
            elif message[skip:].startswith('/ban'):
                client.send(ec(f'BAN {message[skip+5:]}'))

            elif message[skip:].startswith('/unban'):
                client.send(ec(f'UNBAN {message[skip+7:]}'))

            elif message[skip:].startswith('/donut'):
                try:
                    if os.name == 'nt':
                        defprint("Press \"ESC\" to close, press space to pause.")
                        donut()
                except:
                    defprint("No more donut for you!")
                
            elif message[skip:].startswith('/publicip'):
                myip = get('https://api.ipify.org').text
                defprint("Your public IP is: " + myip + "\n")
                
            elif message[skip:].startswith('/ipconfig'):
                try:
                    if os.name == 'nt':
                        defprint(subprocess.run('ipconfig', shell=True, capture_output=True).stdout.decode('utf-8', 'replace'))
                        defprint()
                except:
                    pass

            elif message[skip:].startswith('/ping'):
                try:
                    if os.name == 'nt':
                        defprint(subprocess.run(f'ping {message[skip+6:].strip()}', shell=True, capture_output=True).stdout.decode('utf-8', 'replace'))
                        defprint()
                except:
                    pass

            elif message[skip:].startswith('/credits'):
                defprint('''
                                                    
https://github.com/MattSini912/mschat

Created by:                         Matteo Sinitò (MattSini912)    

Testing:                            Luca Distefano

Concept and basic TCP/IP code:      NeuralNine
Diffie-Hellman implementation:      Hyungjoon Koo
3D ASCII donut:                     codegiovanni
Original pydispo module:            Aakash Patil

''')

            elif message[skip:].startswith('/clear'):
                if os.name == 'nt':
                    os.system('cls')

            elif message[skip:].startswith('/leave'):
                client.close()
                stop_thread = True
                continue
                
            else:
                defprint("Unknown command")
                
        else:
            if message[skip:] == "" or message[skip:].isspace():
                defprint("Message is blank")
                continue
            if len(message[skip:]) > 5000:
                defprint("Message is too long")
                continue
            client.send(ec('> ' + message))

def mygui(txtbox):
    global window
    global stop_thread
    global cur_window
    # Create the Window
    sg.theme('DarkBlue17')
    layout = [
        [sg.Text('MSChat by MattSini912'), sg.Button('Clear Window'), sg.Button('Close Window', button_color=('red'))],
        [sg.Text(f'Connected with: {hostip}'), sg.Button('Online Users')],
        [sg.Text(f'Welcome back "{nickname}"! Check your terminal for more informations.')],
        [sg.Multiline(size=(60, 10), key='OUTPUT', disabled=True, autoscroll=True, expand_x=True, expand_y=True)],
        [sg.Button('C'), sg.Button('SEND'), sg.Button('/'), sg.Input(size=(45, 10), key='INPUT', expand_x=True)], 
        [sg.Button('HELP'), sg.Button('DM'), sg.Button('CREDITS')],  
        ]
    window_icon = get_b64_icon()
    window = sg.Window(f'MSChat: {nickname}', layout, size=(650, 500), disable_close=True, icon=window_icon, resizable=True, font=('Consolas', 10)).Finalize()
    window.TKroot.minsize(480,350)
    window['INPUT'].bind("<Return>", "_Enter")
    cur_window = int(window.TKroot.frame(), base=16) # window id
    #window.minimize()
    window.BringToFront()
    window['INPUT'].set_focus()

    while True:
        if stop_thread:
            break
        event, values = window.read()
        if event == sg.WINDOW_CLOSED or event == 'Close Window':
            txtbox.put("/leave") # Send to write thread
            stop_thread = True
            break
        elif event == 'HELP':
            txtbox.put("/help") # Send to write thread
        elif event == 'CREDITS':
            txtbox.put("/credits") # Send to write thread
        elif event == 'Online Users':
            txtbox.put("/list") # Send to write thread
        elif event == 'DM':
            window['INPUT'].update("/dm name;msg")
        elif event == 'SEND' or event == "INPUT" + "_Enter":
            message = values['INPUT']
            if message != "":
                txtbox.put(message) # Send to write thread
                window['INPUT'].update("")
        elif event == '/':
            window['INPUT'].update("/")
        elif event == 'C':
            window['INPUT'].update("")
        elif event == 'Clear Window':
            window['OUTPUT'].update("")
        elif event == '-PRINT-':
            window['OUTPUT'].update(values[event] + "\n", append=True)


    window.close()

# Creating queues to exchange data beetween threads
txtbox = Queue() # Text to get from the GUI

# Starting Threads For Listening And Writing
receive_thread = threading.Thread(target=receive)
receive_thread.start()

write_thread = threading.Thread(target=write, args=(txtbox, ))
write_thread.start()

mygui_thread = threading.Thread(target=mygui, args=(txtbox, )) #starts when connected
#if enable_gui:
#    mygui_thread.start()
