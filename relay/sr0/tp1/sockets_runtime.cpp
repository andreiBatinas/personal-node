#include "sockets_runtime.h"
#include "logger.h"

std::atomic<int> SocketsRuntime::ref_;
#ifdef WIN32
WSADATA SocketsRuntime::wsa_ = {0};
#endif

int SocketsRuntime::init() {
	PROFILE();

	if(SocketsRuntime::ref_.fetch_add(1) > 1) {
		return 0;
	}
#ifdef WIN32
	LOG_TRACE("=> WSAStartup");
	int rv = WSAStartup(MAKEWORD(2, 2), &SocketsRuntime::wsa_);
	LOG_TRACE("WSAStartup: %d", rv);
	return rv;
#else
	return 0;
#endif
}

void SocketsRuntime::uninit() {
	PROFILE();

	if(SocketsRuntime::ref_.fetch_sub(1) > 0) {
		return;
	}
#ifdef WIN32
	LOG_TRACE("=> WSACleanup");
	int rv = WSACleanup();
	LOG_TRACE("WSACleanup: %d", rv);
#endif
}
