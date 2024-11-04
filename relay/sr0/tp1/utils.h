#pragma once

#include "openssl/ssl.h"
#include <string>

namespace Utils {

constexpr size_t BUFSIZ_SESSION = 6;
constexpr size_t BUFSIZ_IPV4 = 4;
constexpr size_t BUFSIZ_DATA_LENGTH = 2;

int readExactly(SSL* ssl, unsigned char* bytes, int size);

bool readSession(SSL* ssl, unsigned char* session, int size);

bool extractEndpoint(unsigned char session[BUFSIZ_SESSION],
	unsigned char* address, int address_size,
	unsigned short* port);

std::string extractRemoteID(unsigned char session[BUFSIZ_SESSION]);

//	data length: 2 bytes
int readDataLength(SSL* ssl);

int readData(SSL* ssl, unsigned char* data, int length);

} // namespace Utils
