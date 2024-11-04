#pragma once

#include "openssl/ssl.h"
#include "socket.h"

class SSLConnection {
private:
	SSL_CTX* ctx_ = nullptr;
	SSL* ssl_ = nullptr;
	int rv_ = -1;
	int err_ = 0;
public:
	SSLConnection();
	SSLConnection(long tls_min_version, long tls_max_version = -1);
	~SSLConnection();

	int init(long tls_min_version, long tls_max_version = -1);
	bool setSocket(const Socket& socket);
	bool connect();

	operator SSL*() const;
	int last_result() const;
	static int last_error();

private:
	SSLConnection(const SSLConnection&) = delete;
	SSLConnection(SSLConnection&&) = delete;
	SSLConnection& operator=(const SSLConnection&) = delete;
	SSLConnection&& operator=(SSLConnection&&) = delete;
};
