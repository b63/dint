add_library(libdint
    dint.cpp
    clientsm.cpp
    )

add_executable(test_dint
    test_dint.cpp
    )


target_link_libraries(test_dint
    libdint
    ${CMAKE_SOURCE_DIR}/lib/cryptopp/libcryptopp.a)
