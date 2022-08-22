# mschat
**mschat** is a simple command-line application where you can:
- create your own chat server using the [server](MSCHAT%20v.1.3.0/server)
- connect to an existing server using the [client](MSCHAT%20v.1.3.0/client.exe)

Source code for the project can be found [here](MSCHAT%20v.1.3.0/src). Note that I've used a [custom version](MSCHAT%20v.1.3.0/src/pydispo.py) of the [pydispo](https://github.com/aakash30jan/pydispo) module.

Server guide
Client guide

## Encryption
Messages sent using **mschat** are crypted using:
1. [Diffie-Hellman key exchange method](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange) to generate a numeric key shared by server and client
2. [PBKDF2 key derivation function](https://en.wikipedia.org/wiki/PBKDF2) to get a stronger key that can be used with encryption algorithms
3. [Fernet](https://cryptography.io/en/latest/fernet/) to encrypt the message using the derived key

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
As an host, if you want to allow connection only from registered users you have to set `auth` to `true` (make sure to `open` the server).

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
