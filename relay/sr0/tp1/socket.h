#pragma once

#include <string>
#if defined(WIN32)
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#endif

class Socket {
private:
#ifdef WIN32
	UINT_PTR s_ = INVALID_SOCKET;
#else
#define INVALID_SOCKET (-1)
	int s_ = INVALID_SOCKET;
#endif
	int af_ = AF_UNSPEC;
	int rv_ = 0;
public:
	Socket();
	~Socket();

	int handle() const;

	operator bool() const;
	bool operator !() const;

	bool create(int af, int type, int protocol);
	bool connect(const std::string& ip, int port);
	void close();
	void shutdown();

	bool setReuseAddr(bool on);
	bool setTcpNoDelay(bool on);
	int last_result() const;
	static int last_error();

private:
	Socket(const Socket&) = delete;
	Socket(Socket&&) = delete;

	Socket& operator=(const Socket&) = delete;
	Socket&& operator=(Socket&&) = delete;
};
