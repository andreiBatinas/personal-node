# CMakeList.txt : CMake project for tp1, include source and define
# project specific logic here.
#
include(ExternalProject)

# Add source to this project's executable.
add_executable (tp1 "tp1.cpp" "tp1.h" "logger.h" "logger.cpp" "sockets_runtime.h" "sockets_runtime.cpp" "scoped_destruct.h" "scoped_destruct.cpp" "ssl_runtime.cpp" "ssl_runtime.h" "relay_api.h" "relay_starter.cpp" "relay_api.cpp" "relay_starter.h" "utils.cpp" "utils.h" "socket.h" "socket.cpp" "ssl_connection.h" "ssl_connection.cpp")

message(STATUS "CMAKE_VERSION: ${CMAKE_VERSION}")
if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET tp1 PROPERTY CXX_STANDARD 20)
endif()

#
# OpenSSL
#
set(OPENSSL_SOURCE_DIR ${CMAKE_CURRENT_BINARY_DIR}/openssl-src) # default path by CMake
set(OPENSSL_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/openssl)
set(OPENSSL_INCLUDE_DIR ${OPENSSL_INSTALL_DIR}/include)
set(OPENSSL_LIB_DIR ${OPENSSL_INSTALL_DIR}/lib)

# defaults
set(OPENSSL_CONFIGURE_COMMAND perl ${OPENSSL_SOURCE_DIR}/config)
set(OPENSSL_MAKE make)
message(STATUS "Check for Windows needing Configure instead of config")
if (WIN32)
  message(STATUS "Windows: true")

  set(OPENSSL_LIBRARY_SUFFIX "lib")

  # config does not work on Windows
  set(OPENSSL_CONFIGURE_COMMAND perl ${OPENSSL_SOURCE_DIR}/Configure)
  set(OPENSSL_OS_AND_COMPILER ) # default none for non-Windows platforms
  message(STATUS "CMAKE_CACHEVAR_ARCHITECTURE: [${CMAKE_CACHEVAR_ARCHITECTURE}]")
  message(STATUS "CMAKE_BUILD_TYPE: [${CMAKE_BUILD_TYPE}]")
  if("${CMAKE_CACHEVAR_ARCHITECTURE}" STREQUAL "x64")
    # WIN64
    message(STATUS "Settings OpenSSL compiler as: VC-WIN64A")
    set(OPENSSL_OS_AND_COMPILER VC-WIN64A no-asm)
    set(OPENSSL_MAKE nmake)
  elseif("${CMAKE_CACHEVAR_ARCHITECTURE}" STREQUAL "x86")
    # WIN32
    message(STATUS "Settings OpenSSL compiler as: VC-WIN32")
    set(OPENSSL_OS_AND_COMPILER VC-WIN32 no-asm)
    set(OPENSSL_MAKE nmake)
  endif()
else()
  message(STATUS "Win32: false")

  set(OPENSSL_LIBRARY_SUFFIX "so")

  set(OPENSSL_CONFIGURE_COMMAND perl ${OPENSSL_SOURCE_DIR}/config)
  set(OPENSSL_MAKE make)
endif()


# get OpenSSL
ExternalProject_Add(openssl
  SOURCE_DIR ${OPENSSL_SOURCE_DIR}
  GIT_REPOSITORY https://github.com/openssl/openssl.git
  GIT_TAG OpenSSL_1_1_1n
  USES_TERMINAL_DOWNLOAD TRUE
  CONFIGURE_COMMAND
    ${OPENSSL_CONFIGURE_COMMAND}
    --prefix=${OPENSSL_INSTALL_DIR}
    --openssldir=${OPENSSL_INSTALL_DIR}
    --no-shared
    --no-asm
    --no-hw
    --no-engine
    --no-apps
    --no-tests
    --no-external-tests
    --verbose
    ${OPENSSL_OS_AND_COMPILER} 
  BUILD_COMMAND ${OPENSSL_MAKE} /D 
  TEST_COMMAND "" 
  INSTALL_COMMAND ${OPENSSL_MAKE} install 
  INSTALL_DIR ${OPENSSL_INSTALL_DIR} 
  BUILD_BYPRODUCTS ${OPENSSL_INSTALL_DIR}/lib/libssl.${OPENSSL_LIBRARY_SUFFIX} ${OPENSSL_INSTALL_DIR}/lib/libcrypto.${OPENSSL_LIBRARY_SUFFIX}
)

add_library(libssl STATIC IMPORTED GLOBAL)
set_property(TARGET libssl PROPERTY IMPORTED_LOCATION ${OPENSSL_INSTALL_DIR}/lib/libssl.${OPENSSL_LIBRARY_SUFFIX})
add_dependencies(libssl openssl)

add_library(libcrypto STATIC IMPORTED GLOBAL)
set_property(TARGET libcrypto PROPERTY IMPORTED_LOCATION ${OPENSSL_INSTALL_DIR}/lib/libcrypto.${OPENSSL_LIBRARY_SUFFIX})
add_dependencies(libcrypto openssl)

# We cannot use find_library because ExternalProject_Add() is performed at build time.
# And to please the property INTERFACE_INCLUDE_DIRECTORIES,
# we make the include directory in advance.
file(MAKE_DIRECTORY ${OPENSSL_INCLUDE_DIR})

# Make sure it can be included
message(STATUS "OPENSSL_INCLUDE_DIR: ${OPENSSL_INCLUDE_DIR}")

target_include_directories(tp1 PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(tp1 libcrypto libssl)
if (WIN32)
target_link_libraries(tp1 libcrypto libssl ws2_32)
endif()
