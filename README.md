# MSCHAT
                         _           _    
      _ __ ___  ___  ___| |__   __ _| |_  
     | '_ ` _ \/ __|/ __| '_ \ / _` | __|
     | | | | | \__ \ (__| | | | (_| | |_ 
     |_| |_| |_|___/\___|_| |_|\__,_|\__|

## Read the [WIKI](https://github.com/MattSini912/mschat/wiki/) for deeper information.

**mschat** is a simple application that allows you:
- create your own chat server using the [server](MSCHAT/server)
- connect to an existing server using the [client](MSCHAT/client.exe)

Source code for the project can be found [here](MSCHAT/src). Note that I've used a [custom version](MSCHAT/src/pydispo.py) of the [pydispo](https://github.com/aakash30jan/pydispo) module.

## Encryption
Messages sent using **mschat** are encrypted using:
1. [Diffie-Hellman key exchange method](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange) to generate a numeric key shared by server and client
2. [PBKDF2 key derivation function](https://en.wikipedia.org/wiki/PBKDF2) to get a stronger key that can be used with encryption algorithms
3. [Fernet](https://cryptography.io/en/latest/fernet/) to encrypt the message using the derived key

> DISCLAIMER: encryption effectiveness is not guaranteed by any official standard.

## GUI

![gui](https://user-images.githubusercontent.com/106877447/203284504-11b58c6b-3ed1-4629-8d2f-0a9ece94a8b5.PNG)

### Top [WIKI](https://github.com/MattSini912/mschat/wiki/) pages:
- [How to download the client](https://github.com/MattSini912/mschat/wiki/client_download)
- [Connecting to a server](https://github.com/MattSini912/mschat/wiki/login)
- [Signing up on a server](https://github.com/MattSini912/mschat/wiki/register)
