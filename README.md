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
