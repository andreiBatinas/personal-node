#pragma once

#if 0

#include <string>
#include <thread>
#include "sockets_runtime.h"
#include "openssl/ssl.h"

class RelayConnectionStarter {
private:
	int rv_ = -1;

	int relayPort_ = -1;
	std::string relayIP_;
	socket_t sock_ = -1;

	const SSL_METHOD* method_ = nullptr;
	SSL_CTX* ctx_ = nullptr;
	SSL* ssl_ = nullptr;
	BIO* bioIn_ = nullptr;
	BIO* bioOut_ = nullptr;
	std::thread tlsThread_;

public:
	RelayConnectionStarter(const std::string& relayIP, int relayPort);

	int start();
	int stop();

	static void init(const std::string& relayIP, int relayPort);
	bool openRelayConnection();

	bool connectSocket();
	bool createSslContext();

	void RunTlsIO();
	int run();
};

#endif
