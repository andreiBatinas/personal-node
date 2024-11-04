#include "socket.h"
#include "logger.h"
#include <cassert>

Socket::Socket() {
}

Socket::~Socket() {
}

int Socket::handle() const {
#ifdef WIN32
	if(s_ == INVALID_SOCKET)
		return -1;
	return static_cast<int>(s_);
#else
	return s_;
#endif
}

Socket::operator bool() const {
	return s_ != INVALID_SOCKET;
}
bool Socket::operator !() const {
	return s_ == INVALID_SOCKET;
}

bool Socket::create(int af, int type, int protocol) {
	PROFILE();

	assert(s_ == INVALID_SOCKET);
	af_ = af;
	s_ = socket(af, type, protocol);
	return s_ != INVALID_SOCKET;
}

bool Socket::connect(const std::string& ip, int port) {
	struct sockaddr_in addr = {0};
	memset(&addr, 0, sizeof(addr));

	addr.sin_family = af_;
	addr.sin_port = htons(port);
	LOG_TRACE("=> inet_pton: %s:%d", ip.c_str(), port);
	rv_ = inet_pton(af_, ip.c_str(), &addr.sin_addr);
	if(rv_ == 1) {
		LOG_TRACE("inet_pton: %d", rv_);
	}
	else {
		LOG_ERROR("inet_pton: %d", rv_);
	}
	assert(rv_ == 1);
			
	LOG_TRACE("=> connect");
	rv_ = ::connect(s_, (const sockaddr *)&addr, sizeof(addr));
	if(rv_ != 0) {
		LOG_ERROR("connect: %d", rv_);
	}
	else {
		LOG_TRACE("connect: %d", rv_);
	}

	return rv_ == 0;
}

void Socket::close() {
	if(!operator bool())
		return;
	rv_ = closesocket(s_);
	LOG_TRACE("closesocket: %d", rv_);
	s_ = INVALID_SOCKET;
}

void Socket::shutdown() {
	PROFILE();

	if(s_ != INVALID_SOCKET) {
		LOG_TRACE("=> closesocket: sockfd: %d", s_);
		rv_ = closesocket(s_);
		LOG_TRACE("closesocket: %d", rv_);
		s_ = INVALID_SOCKET;
	}
}

bool Socket::setReuseAddr(bool on) {
	if(s_ == INVALID_SOCKET)
		return false;
	LOG_TRACE("=> setsockopt SO_REUSEADDR");
	int opt = on ? 1 : 0;
	rv_ = setsockopt(s_, SOL_SOCKET, SO_REUSEADDR,
		(const char*)&opt, sizeof(opt));
	LOG_TRACE("setsockopt SO_REUSEADDR: %d", rv_);
	return rv_ == 0;
}

bool Socket::setTcpNoDelay(bool on) {
	if(s_ == INVALID_SOCKET)
		return false;
	LOG_TRACE("=> setsockopt SO_REUSEADDR");
	int opt = on ? 1 : 0;
	rv_ = setsockopt(s_, IPPROTO_TCP, TCP_NODELAY,
		(const char*)&opt, sizeof(opt));
	LOG_TRACE("setsockopt SO_REUSEADDR: %d", rv_);
	return rv_ == 0;
}

int Socket::last_result() const {
	return rv_;
}

int Socket::last_error() {
#ifdef WIN32
	return WSAGetLastError();
#else
	return errno;
#endif
}
