#include "utils.h"
#include "logger.h"

namespace Utils {

int readExactly(SSL* ssl, unsigned char* bytes, int size) {
	if(ssl == nullptr || bytes == nullptr || size <= 0) {
		return false;
	}
	int received = SSL_read(ssl, bytes, size);
	LOG_TRACE("received: %d", received);
	return received;
}

//	session ID: 6 bytes
//		4 bytes [0..3] IPv4 address
//		2 bytes [4..5] port
bool readSession(SSL* ssl, unsigned char* session, int size) {
	if(ssl == nullptr || session == nullptr || size != BUFSIZ_SESSION)
		return false;
	memset(&session[0], 0, size);
	if(Utils::readExactly(ssl, session, size) != BUFSIZ_SESSION) {
		LOG_ERROR("session: invalid packet or connection closed");
		return false;
	}
	return true;
}

bool extractEndpoint(unsigned char session[BUFSIZ_SESSION],
	unsigned char* address, int address_size,
	unsigned short* port) {
	if(address == nullptr || address_size != BUFSIZ_IPV4 || port == nullptr)
		return false;
	memcpy(&address[0], &session[0], BUFSIZ_IPV4);
	*port = ((session[4] & 0xFF) << 8) | (session[5] & 0xFF);
	return true;
}

std::string extractRemoteID(unsigned char session[BUFSIZ_SESSION]) {
	unsigned char address[4] = {0};
	memcpy(&address[0], &session[0], BUFSIZ_IPV4);

	unsigned short port = ((session[4] & 0xFF) << 8) | (session[5] & 0xFF);

	char buffer[sizeof("xxx.xxx.xxx.xxx:xxxxxx") + 1] = {0};
	int n = snprintf(buffer, sizeof(buffer), "%u.%u.%u.%u:%u",
		address[0], address[1], address[2], address[3],
		port);

	if(n <= 0)
		return {};

	return std::string(buffer);
}

//	data length: 2 bytes
int readDataLength(SSL* ssl) {
	unsigned char lengthBytes[Utils::BUFSIZ_DATA_LENGTH] = {0};
	memset(&lengthBytes[0], 0, sizeof(lengthBytes));
	if(!Utils::readExactly(ssl, lengthBytes, Utils::BUFSIZ_DATA_LENGTH)) {
		LOG_ERROR("could not read data length");
		return -1;
	}
	int payloadLength = (
		((lengthBytes[0] & 0xFF) << 8) |
		(lengthBytes[1] & 0xFF)
	) & 0xFFFF;
	LOG_TRACE("data length: %d", payloadLength);
	return payloadLength;
}

int readData(SSL* ssl, unsigned char* data, int length) {
	if(ssl == nullptr || data == nullptr || length <= 0)
		return false;

	if(Utils::readExactly(ssl, data, length) != length) {
		LOG_WARNING("data: invalid packet or connection closed");
		return false;
	}
	LOG_TRACE("data received: %d", length);
	return true;
}

} // namespace Utils
