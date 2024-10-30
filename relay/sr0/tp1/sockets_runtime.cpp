#include "sockets_runtime.h"
#include <cerrno>
#if defined(WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#ifdef WIN32
WSADATA SocketsRuntime::wsa_ = {0};
#endif
int SocketsRuntime::rv_ = -EINVAL;

int SocketsRuntime::init() {
#ifdef WIN32
	rv_ = WSAStartup(MAKEWORD(2, 2), &wsa_);
#else
	rv_ = 0;
#endif
	return rv_;
}

void SocketsRuntime::uninit() {
#ifdef WIN32
	WSACleanup();
#endif
	rv_ = -EINVAL;
}

int SocketsRuntime::last_error() {
#if defined(WIN32)
	return WSAGetLastError();
#else
	return errno;
#endif
}

int SocketsRuntime::get_addrinfo(const char* node, const char* service,
	const struct addrinfo* hints, struct addrinfo** result) {
	return getaddrinfo(node, service, hints, result);
}

void SocketsRuntime::free_addrinfo(addrinfo* relay_addrinfo) {
	if(relay_addrinfo != nullptr) {
		freeaddrinfo(relay_addrinfo);
	}
}

