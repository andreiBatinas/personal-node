#pragma once

#if defined(WIN32)
#include <winsock2.h>
typedef SOCKET socket_t;
#else
typedef int socket_t;
#endif

class SocketsRuntime {
private:
#ifdef WIN32
	static WSADATA wsa_;
#endif
	static int rv_;

public:
	static int init();
	static void uninit();

	static int last_error();

	static int get_addrinfo(const char* node, const char* service,
		const struct addrinfo* hints, struct addrinfo** result);
	static void free_addrinfo(addrinfo* relay_addrinfo);

private:
	SocketsRuntime() = delete;
	~SocketsRuntime() = delete;
	SocketsRuntime(const SocketsRuntime&) = delete;
	SocketsRuntime(SocketsRuntime&&) = delete;
	SocketsRuntime& operator=(const SocketsRuntime&) = delete;
	SocketsRuntime&& operator=(SocketsRuntime&&) = delete;
};
