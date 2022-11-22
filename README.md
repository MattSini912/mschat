# mschat (guide needs to be updated to 1.4.0)
**mschat** is a simple command-line application where you can:
- create your own chat server using the [server](MSCHAT/server)
- connect to an existing server using the [client](MSCHAT/client.exe)

Source code for the project can be found [here](MSCHAT/src). Note that I've used a [custom version](MSCHAT/src/pydispo.py) of the [pydispo](https://github.com/aakash30jan/pydispo) module.

## Encryption
Messages sent using **mschat** are crypted using:
1. [Diffie-Hellman key exchange method](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange) to generate a numeric key shared by server and client
2. [PBKDF2 key derivation function](https://en.wikipedia.org/wiki/PBKDF2) to get a stronger key that can be used with encryption algorithms
3. [Fernet](https://cryptography.io/en/latest/fernet/) to encrypt the message using the derived key

## GUI (1.4.0+)
Starting from version 1.4.0 the application is provided with a simple graphical interface with useful features:

![gui](https://user-images.githubusercontent.com/106877447/203284504-11b58c6b-3ed1-4629-8d2f-0a9ece94a8b5.PNG)

- **Send**: sends the message in the typing box, you can also press ENTER
- **Help**: shows all the commands
- **Online users**: shows the connected users
- **Close window**: makes you leave the chat
- **/**: adds '/' character
- **DM**: adds a template for direct messages
- **C**: clears the input
- **Clear window**: clears all text

The interface enables you to write text while receiving messages. It's not supported for the authentication functions (`/register` and `/delete`) so you must interact with the terminal to use them. The GUI is launched automatically with the default `/login` function. 

To start the application without the GUI use the `/nogui` function.

```
Enter server's IP adress (default = 127.0.0.1) ->
Enter server's port (default = 55555) ->
/login (default), /register, /delete or /nogui -> /nogui
...
```

## How to connect to a server without authentication

1. open your client 
2. insert server's address
3. choose a nickname
```
Enter server's IP adress (default = 127.0.0.1) -> 123.45.67.89
Enter server's port (default = 55555) ->
/login (default), /register or /delete ->
Your nickname -> Steve
Password for profile (leave blank if not required) ->
Connecting...
Making requests...
Encrypted tunnel active!
[2022/08/01 12:00:01] >>> "Steve" joined!
[2022/08/01 12:00:01] Connected to server as "Steve"! 1 users online. List of commands: /help
```

## Authentication
As an host, if you want to allow connection only from registered users, you have to set `auth` to `true` (make sure to `open` the server).

As a user: 
1. open your client 
2. insert server's address
3. type `/register` when asked
4. complete with your data
```
Enter server's IP adress (default = 127.0.0.1) -> 123.45.67.89
Enter server's port (default = 55555) ->
/login (default), /register or /delete -> /register
Choose a nickname -> RandomNick
Email -> example@mail.com
Password -> NotPassword
Connecting...
Making requests...
Encrypted tunnel active!
[2022/08/01 12:00:01] Within 5 minutes send an email at: abunchofnonsense@1secmail.net with this code as subject: 123456 and wait
```
5. follow the instructions

![Cattura](https://user-images.githubusercontent.com/106877447/185943390-510e64c4-8d56-4983-a9c9-b0b6827ec078.PNG)
```
...
[2022/08/01 12:00:01] Within 5 minutes send an email at: abunchofnonsense@1secmail.net with this code as subject: 123456 and wait
[2022/08/01 12:03:00] User "RandomNick" registered
Operation completed!
```

6. login
```
Enter server's IP adress (default = 127.0.0.1) -> 123.45.67.89
Enter server's port (default = 55555) ->
/login (default), /register or /delete ->
Your nickname -> RandomNick
Password for profile (leave blank if not required) -> NotPassword
Connecting...
Making requests...
Encrypted tunnel active!
[2022/08/01 12:05:01] >>> "RandomNick" joined!
[2022/08/01 12:05:01] Connected to server as "RandomNick"! 1 users online. List of commands: /help
```
To delete your profile you have to type `/delete` instead of `/register`
## How to start a server
1. open your server 
2. insert your private IP:
    - from the command prompt type `ipconfig`, your private IP should be something like 192.168.1.5
    - type 127.0.0.1 if you are using a service like [ngrok](https://ngrok.com/) or you want to connect only from your machine (e.g. for testing or management)
```
Enter your private IP (default = 127.0.0.1) -> 192.168.1.5
Server started! Your public IP is: 123.45.67.89:55555
SERVER password is: k702ipeiHInsSehCdB4w
ADMIN password is: xBtygv5di8mgBH4bWyPq
Type "/settings help" on terminal to show server's commands and settings
Server is listening...
```
3. log in as SERVER
```
Enter server's IP adress (default = 127.0.0.1) -> 123.45.67.89
Enter server's port (default = 55555) ->
/login (default), /register or /delete ->
Your nickname -> SERVER
Password for profile (leave blank if not required) -> k702ipeiHInsSehCdB4w
Connecting...
Making requests...
Encrypted tunnel active!
[2022/08/01 12:15:00] >>> "SERVER" joined!
[2022/08/01 12:15:00] Connected to server as "SERVER"! 1 users online. List of commands: /help
```
4. type `/settings help` to show all server's commands

## Recommended folder structure
```
MSCHAT
    |
    pydispo.py [if using py]
    mycryptfunc.py [if using py]
    client.exe/py
    server
        |
        mycryptfunc.py [if not fetched before by a py]
        server.exe/py
        [server files]
```
    
