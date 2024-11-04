#pragma once

#include <atomic>
#if defined(WIN32)
#include <winsock2.h>
#else
typedef int socket_t;
#endif

class SocketsRuntime {
private:
	static std::atomic<int> ref_;
#ifdef WIN32
	static WSADATA wsa_;
#endif
private:
	SocketsRuntime() = delete;
	SocketsRuntime(const SocketsRuntime&) = delete;
	SocketsRuntime(SocketsRuntime&&) = delete;
	~SocketsRuntime() = delete;
	
	SocketsRuntime& operator=(const SocketsRuntime&) = delete;
	SocketsRuntime&& operator=(SocketsRuntime&&) = delete;
public:
	static int init();
	static void uninit();
};
