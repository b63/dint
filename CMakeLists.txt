cmake_minimum_required(VERSION 3.8)
project ("dint" CXX)

set(CMAKE_CXX_STANDARD 17)


if (WIN32)
    message(FATAL_ERROR "windows build environment not supported")
endif()

set(CMAKE_CXX_COMPILER g++)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_BINARY_DIR "${CMAKE_SOURCE_DIR}/build")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin")

add_compile_options(-ggdb)

include_directories(BEFORE ${CMAKE_SOURCE_DIR}/include)
include_directories(BEFORE ${CMAKE_SOURCE_DIR}/lib/)
include_directories(BEFORE ${CMAKE_SOURCE_DIR}/logger/)

find_library(CRYPTOPP
    NAMES libcryptopp.a
    HINTS ${CMAKE_SOURCE_DIR}/lib/cryptopp)

add_subdirectory(${CMAKE_SOURCE_DIR}/logger)

add_subdirectory(${CMAKE_SOURCE_DIR}/src)
