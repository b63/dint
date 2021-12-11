add_library(dint
    server.cpp
    client.cpp
    cipher.cpp
    serversm.cpp
    clientsm.cpp
    dint.cpp
    util.cpp
    # headers
    )

# tests
add_executable(test_rsa tests/test_rsa.cpp util.cpp)
target_link_libraries(test_rsa ${CRYPTOPP} logger)


add_executable(test_server1 dint.cpp tests/test_server.cpp)
target_link_libraries(test_server1 dint logger ${CRYPTOPP} pthread )

add_executable(test_client1 dint.cpp tests/test_client.cpp)
target_link_libraries(test_client1 dint logger ${CRYPTOPP} pthread)
