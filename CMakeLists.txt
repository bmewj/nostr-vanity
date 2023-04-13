cmake_minimum_required (VERSION 3.13)
project(nostr-vanity CXX C)
enable_language(CXX)
set(CMAKE_CXX_STANDARD 17)

set(SECP256K1_ENABLE_MODULE_SCHNORRSIG ON CACHE BOOL "Secp256k1 Enable module Schnorr signatures")
set(SECP256K1_BUILD_SHARED OFF CACHE BOOL "Build shared library.")
set(SECP256K1_BUILD_BENCHMARK OFF CACHE BOOL "Build benchmarks.")
set(SECP256K1_BUILD_TESTS OFF CACHE BOOL "Build tests.")
set(SECP256K1_BUILD_EXHAUSTIVE_TESTS OFF CACHE BOOL "Build exhaustive tests.")

add_subdirectory(lib/secp256k1)

add_executable(nostr-vanity src/main.cpp)
target_include_directories(nostr-vanity PUBLIC lib/secp256k1/include)
target_link_libraries(nostr-vanity secp256k1_static)
