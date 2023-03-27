DinT
-----
A protocol on top of TCP that provides
a secure encrypted channel through which two parties can communicate. Here a ‘secure channel’ means that
an unauthorized third party listening in on the information being exchanged would not be able to easily
decipher it.
Implementation details:
- Employs a TLS-like handshake that uses Diffie-Hellman to establish a master key, and using that
master key to encrypt all subsequent traffic.
- Cryptographic algorithms used: AES-128, SHA256, RSA, HMAC.


Below are the state diagrams showing the series of messages that would be exchanged between client/server over TCP
to establish a shared secret over an open channel.

State diagram of the client:
![client state machine](https://github.com/b63/dint/blob/master/resources/clientsm.png?raw=true)

State diamgram of the server:
![client state machine](https://github.com/b63/dint/blob/master/resources/serversm.png?raw=true)

Building
-----

Clone the repository and install all needed dependencies, which will
mostly include
  - cmake >= 3.8
  - make
  - Crypto++ (included as git submodule)


After cloning the repository, fetch the Crypto++ library which is
included as a git submodule  under `lib/cyprotpp` and build it
by running `make`.
```bash
    git clone https://github.com/b63/dint && cd dint
    git submodule init && git submodule update
    cd lib/cryptopp && make
```

The default cmake script looks for Crypto++ under `lib/cryptopp`,
so if Crypto++ is already installed as a system library then
`CMakeLists.txt` may need to be modified.


After Crypto++ is built, DinT can be built under `build/` by running
```bash
    cmake -Bbuild && cmake --build build
```

After the build is finished, the test server/client binaries as
well as the static library `libdint.a` will be found under `bin/`.
