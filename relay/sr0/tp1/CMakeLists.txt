# CMakeList.txt : CMake project for tp1, include source and define
# project specific logic here.
#
include(ExternalProject)

# Add source to this project's executable.
add_executable (tp1 "tp1.cpp" "tp1.h")

message(STATUS "CMAKE_VERSION: ${CMAKE_VERSION}")
if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET tp1 PROPERTY CXX_STANDARD 20)
endif()

# OpenSSL NASM
if(0)
message(STATUS "CMAKE_CURRENT_BINARY_DIR: ${CMAKE_CURRENT_BINARY_DIR}")
if (WIN32)
  message(STATUS "Windows: true")
  
  project(nasm-download NONE)
  set(BUILD_TOOLS_DIR ${CMAKE_CURRENT_BINARY_DIR}/build_tools)
  set(NASM_VER "2.16.03")
  if("${CMAKE_CACHEVAR_ARCHITECTURE}" STREQUAL "x64")
    set(NASM_LINK "https://www.nasm.us/pub/nasm/releasebuilds/${NASM_VER}/win64/nasm-${NASM_VER}-win64.zip")
  elseif("${CMAKE_CACHEVAR_ARCHITECTURE}" STREQUAL "x86")
    set(NASM_LINK "https://www.nasm.us/pub/nasm/releasebuilds/${NASM_VER}/win32/nasm-${NASM_VER}-win32.zip")
  endif()

  file(DOWNLOAD ${NASM_LINK} ${BUILD_TOOLS_DIR}/nasm.zip)
  execute_process(
	  COMMAND ${CMAKE_COMMAND} -E tar xzf ${BUILD_TOOLS_DIR}/nasm.zip
	  WORKING_DIRECTORY ${BUILD_TOOLS_DIR}
  )

  message(STATUS "[1] CMAKE_PROGRAM_PATH: ${CMAKE_PROGRAM_PATH}")

  set(NASM_PATH "${BUILD_TOOLS_DIR}/nasm-${NASM_VER}/nasm.exe")
  message(STATUS "NASM_PATH: ${NASM_PATH}")
  # cmake_path(APPEND ${NASM_PATH})
  LIST(APPEND CMAKE_PROGRAM_PATH ${NASM_PATH})

  message(STATUS "[2] CMAKE_PROGRAM_PATH: ${CMAKE_PROGRAM_PATH}")
endif()
endif() #if 0


#
# Add tests and install targets if needed.
#
# OpenSSL
set(OPENSSL_SOURCE_DIR ${CMAKE_CURRENT_BINARY_DIR}/openssl-src) # default path by CMake
set(OPENSSL_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/openssl)
set(OPENSSL_INCLUDE_DIR ${OPENSSL_INSTALL_DIR}/include)

# defaults
set(OPENSSL_CONFIGURE_COMMAND perl ${OPENSSL_SOURCE_DIR}/config)
set(OPENSSL_MAKE make)
message(STATUS "Check for Windows needing Configure instead of config")
if (WIN32)
  message(STATUS "Windows: true")
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
  set(OPENSSL_CONFIGURE_COMMAND perl ${OPENSSL_SOURCE_DIR}/config)
  set(OPENSSL_MAKE make)
endif()


# get OpenSSL
ExternalProject_Add(
  OpenSSL
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
    --verbose
    ${OPENSSL_OS_AND_COMPILER}
  BUILD_COMMAND ${OPENSSL_MAKE} /D
  TEST_COMMAND ""
  INSTALL_COMMAND ${OPENSSL_MAKE} install
  INSTALL_DIR ${OPENSSL_INSTALL_DIR}
)

# We cannot use find_library because ExternalProject_Add() is performed at build time.
# And to please the property INTERFACE_INCLUDE_DIRECTORIES,
# we make the include directory in advance.
file(MAKE_DIRECTORY ${OPENSSL_INCLUDE_DIR})

add_library(OpenSSL::SSL STATIC IMPORTED GLOBAL)
set_property(TARGET OpenSSL::SSL PROPERTY IMPORTED_LOCATION ${OPENSSL_INSTALL_DIR}/lib/libssl.${OPENSSL_LIBRARY_SUFFIX})
set_property(TARGET OpenSSL::SSL PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${OPENSSL_INCLUDE_DIR})
add_dependencies(OpenSSL::SSL OpenSSL)

add_library(OpenSSL::Crypto STATIC IMPORTED GLOBAL)
set_property(TARGET OpenSSL::Crypto PROPERTY IMPORTED_LOCATION ${OPENSSL_INSTALL_DIR}/lib/libcrypto.${OPENSSL_LIBRARY_SUFFIX})
set_property(TARGET OpenSSL::Crypto PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${OPENSSL_INCLUDE_DIR})
add_dependencies(OpenSSL::Crypto OpenSSL)
