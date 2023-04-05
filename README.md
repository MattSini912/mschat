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

- **Send**: send the message in the typing box, you can also press ENTER
- **Help**: show all the commands
- **Online users**: show connected users
- **Close window**: makes you leave the chat
- **/**: add '/' character
- **DM**: add a template for direct messages
- **C**: clear the input
- **Clear window**: clear all text

The interface enables you to write text while receiving messages. It's not supported for the authentication functions (`/register` and `/delete`): you must interact with the terminal to use them. The GUI is launched automatically with the default `/login` function. 

To start the application without the GUI use the `/nogui` function.
