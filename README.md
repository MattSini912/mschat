# mschat
`mschat` is a simple command-line application where you can:
- create your own chat server using the [server](MSCHAT%20v.1.3.0/server)
- connect to an existing server using the [client](MSCHAT%20v.1.3.0/client.exe)

Source code for the project can be found [here](MSCHAT%20v.1.3.0/src). Note that I've used a [custom version](MSCHAT%20v.1.3.0/src/pydispo.py) of the module [pydispo](https://github.com/aakash30jan/pydispo).

Server guide
Client guide

Messages sent using `mschat` are crypted using:
1. [Diffie-Hellman key exchange method](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange) to generate a numeric key shared by server and client
2. [PBKDF2 key derivation function](https://en.wikipedia.org/wiki/PBKDF2) to get a stronger key that can be used with encryption algorithms
3. [Fernet](https://cryptography.io/en/latest/fernet/) to encrypt the message using the key
