#include "tp1.h"

#if defined(WIN32)
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#endif
#include <cassert>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>

#include "logger.h"
#include "relay_api.h"
#include "scoped_destruct.h"
#include "sockets_runtime.h"
#include "ssl_runtime.h"

namespace tests {
namespace _1 {
void test() {
	PROFILE();

	do {
		int rv = SocketsRuntime::init();
		if(rv != 0) {
			LOG_ERROR("[" __FUNCTION__ "] %s => %d", "SocketRuntime::init()", rv);
			break;
		}
		LOG_INFO("[" __FUNCTION__ "] %s", "SocketRuntime::init()");

		rv = SSLRuntime::init();
		if(rv != 0) {
			LOG_ERROR("[" __FUNCTION__ "] %s => %d", "SSLRuntime::init()", rv);
			break;
		}
		LOG_INFO("[" __FUNCTION__ "] %s", "SSLRuntime::init()");

		struct relay_connection_t relayer;
		rv = RelayConnection_Create(&relayer, "193.29.58.141", 19002);
		LOG_INFO("[" __FUNCTION__ "] %s => %d", "RelayConnection_Create", rv);
		if(rv != 0) {
			LOG_ERROR("[" __FUNCTION__ "] %s: fail %d", "RelayConnection_Create", rv);
			break;
		}

		rv = RelayConnection_Start(&relayer);
		LOG_INFO("[" __FUNCTION__ "] %s => %d", "RelayConnection_Start", rv);
		if(rv != 0) {
			LOG_ERROR("[" __FUNCTION__ "] %s => %d", "RelayConnection_Create", rv);
			break;
		}
		else {
			//	run while keypress
			LOG_INFO("Press 'q' to exit.");
			for(;;) {
				char ch = std::cin.get();
				if(ch == 'q') {
					break;
				}
			}
		}

		rv = RelayConnection_Destroy(&relayer);
		LOG_INFO("[" __FUNCTION__ "] %s => %d", "RelayConnection_Destroy", rv);

	} while(0);

	LOG_INFO("[" __FUNCTION__ "] %s", "SSLRuntime::uninit()");
	SSLRuntime::uninit();
	SocketsRuntime::uninit();
}
} // _1

namespace _2 {

class RelayConnectionStarter {
private:
	static int relayPort;
	static std::string relayIP;
	static SOCKET sockfd;
public:
	static void shutdown() {
		PROFILE();
		if(sockfd != INVALID_SOCKET) {
			LOG_INFO("=> closesocket: sockfd: %d", sockfd);
			int rv = closesocket(sockfd);
			LOG_INFO("closesocket: %d", rv);
		}
	}
	static void init(const std::string& relayIP, int relayPort) {
		RelayConnectionStarter::relayIP = relayIP;
		RelayConnectionStarter::relayPort = relayPort;
		openRelayConnection();
	}
	static void openRelayConnection() {
		int rv;
		const SSL_METHOD* tls12_method = nullptr;
		SSL_CTX* ctx = nullptr;
		//BIO* bio = nullptr;
		SSL* ssl = nullptr;
		sockfd = INVALID_SOCKET;
		int opt;
		do {
			if(relayIP.empty() || relayPort <= 0)
				break;

			WSADATA wsa = {0};
			LOG_INFO("=> WSAStartup");
			rv = WSAStartup(MAKEWORD(2, 2), &wsa);
			LOG_INFO("WSAStartup: %d");

			//	plain socket
			LOG_INFO("=> socket");
			sockfd = socket(AF_INET, SOCK_STREAM, 0);
			LOG_INFO("socket: sockfd:%lld", sockfd);

			LOG_INFO("=> setsockopt SO_REUSEADDR");
			opt = 1;
			rv = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));
			LOG_INFO("setsockopt SO_REUSEADDR: %d", rv);

			LOG_INFO("=> setsockopt TCP_NODELAY");
			opt = 1;
			rv = setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (const char *)&opt, sizeof(opt));
			LOG_INFO("setsockopt SO_REUSEADDR: %d", rv);
			
			struct sockaddr_in addr;
			memset(&addr, 0, sizeof(addr));
			addr.sin_family = AF_INET;
			addr.sin_port = htons(relayPort);
			LOG_INFO("=> inet_pton: %s:%d", relayIP.c_str(), relayPort);
			rv = inet_pton(AF_INET, relayIP.c_str(), &addr.sin_addr);
			LOG_INFO("inet_pton: %d", rv);
			
			LOG_INFO("=> connect");
			rv = connect(sockfd, (const sockaddr *)&addr, sizeof(addr));
			LOG_INFO("connect: %d", rv);

			//	init SSL
			rv = SSL_load_error_strings();
			LOG_INFO("SSL_load_error_strings => %d", rv);
			rv = ERR_load_BIO_strings();
			LOG_INFO("ERR_load_BIO_strings => %d", rv);
			rv = OpenSSL_add_all_algorithms();
			LOG_INFO("OpenSSL_add_all_algorithms => %d", rv);
			rv = SSL_library_init();
			LOG_INFO("SSL_library_init => %d", rv);

			//	context
			LOG_INFO("=> TLSv1_2_client_method");
			tls12_method = TLSv1_2_client_method();
			LOG_INFO("tls12_method: %p", tls12_method);

			LOG_INFO("=> SSL_CTX_new");
			ctx = SSL_CTX_new(tls12_method);
			LOG_INFO("ctx: %p", ctx);
			//	TODO? SSL_CTX_set_options

			//	ssl
			LOG_INFO("=> SSL_new");
			ssl = SSL_new(ctx);
			LOG_INFO("ssl: %p", ssl);

			LOG_INFO("=> SSL_set_min_proto_version");
			rv = SSL_set_min_proto_version(ssl, TLS1_2_VERSION);
			LOG_INFO("SSL_set_min_proto_version: %d", rv);

			LOG_INFO("=> SSL_set_max_proto_version");
			rv = SSL_set_max_proto_version(ssl, TLS1_2_VERSION); // TLS_MAX_VERSION
			LOG_INFO("SSL_set_max_proto_version: %d", rv);

			LOG_INFO("=> SSL_set_ciphersuites");
			rv = SSL_set_ciphersuites(ssl, 
				TLS1_RFC_RSA_WITH_AES_256_SHA        ":"
				TLS1_RFC_RSA_WITH_AES_128_SHA        ":"
				TLS1_RFC_RSA_WITH_AES_256_GCM_SHA384 ":"
				TLS1_RFC_RSA_WITH_AES_128_GCM_SHA256
			);
			LOG_INFO("SSL_set_ciphersuites: %d", rv);

			//	TODO SSL_set_options ?

			LOG_INFO("=> SSL_set_fd");
			rv = SSL_set_fd(ssl, (int)sockfd);
			LOG_INFO("SSL_set_fd: %d", rv);

			LOG_INFO("=> SSL_connect");
			rv = SSL_connect(ssl);
			LOG_INFO("SSL_connect: %d", rv);

			//	TODO starts thread to read from servers and send to the relay
			std::thread tlsThread = std::move(
				std::thread([&]() -> void {
					RunTlsIO(ssl, RelayConnectionStarter::sockfd);
					}));
			LOG_INFO("[" __FUNCTION__ "] => tlsThread: %p", tlsThread.native_handle());
			if(tlsThread.native_handle() == nullptr) {
				rv = -ENOEXEC;
				LOG_INFO("[" __FUNCTION__ "] => tlsThread_ fail: %d", errno);
			}
			else {
				LOG_INFO("[" __FUNCTION__ "] => %s", "tlsThread_.join()");
				tlsThread.join();
				LOG_INFO("[" __FUNCTION__ "] => %s done", "tlsThread_.join()");
			}
		} while(0);

		//	cleanup
		LOG_INFO("=> closesocket");
		if(sockfd != INVALID_SOCKET) {
			rv = closesocket(sockfd);
			LOG_INFO("closesocket: %d", rv);
			sockfd = INVALID_SOCKET;
		}

		LOG_INFO("=> SSL_CTX_free: ctx:%p", ctx);
		if(ctx != nullptr)
			SSL_CTX_free(ctx);

		LOG_INFO("=> EVP_cleanup");
		EVP_cleanup();

		LOG_INFO("=> WSACleanup");
		rv = WSACleanup();
		LOG_INFO("WSACleanup: %d");

		LOG_INFO("DONE");
	}

	static void RunTlsIO(SSL* ssl, SOCKET sockfd) {
		PROFILE();

		//	TODO starts thread that reads data from the destination servers and sends it back to the relay

		//	read from relay
		int end_loop = 0;
		for(; end_loop == 0; ) {
			//	readFromRelay()
			do {
				//	1. session ID: 6 bytes
#define BUFSIZ_SESSION (6)
				unsigned char session[BUFSIZ_SESSION] = {0};
				memset(&session[0], 0, sizeof(session));
				int received = SSL_read(ssl, &session[0], BUFSIZ_SESSION);
				LOG_INFO("received: %d", received);
				if(received != BUFSIZ_SESSION) {
					LOG_INFO("session: invalid packet or connection closed");
					end_loop = 1;
					break;
				}

				//	6 bytes
				//		4 bytes [0..3] IPv4 address
				//		2 bytes [4..5] port
				unsigned char address[4] = {0};
				memcpy(&address[0], &session[0], 4);
				unsigned short port = ((session[4] & 0xFF) << 8) | (session[5] & 0xFF);
				LOG_INFO("[%u.%u.%u.%u:%u] received packet",
					address[0], address[1], address[2], address[3],
					port);

				//	2. data length: 2 bytes
#define BUFSIZ_DATA_LENGTH (2)
				unsigned char lengthBytes[BUFSIZ_DATA_LENGTH] = {0};
				memset(&lengthBytes[0], 0, sizeof(lengthBytes));
				received = SSL_read(ssl, &lengthBytes[0], BUFSIZ_DATA_LENGTH);
				LOG_INFO("received: %d", received);
				// memcpy(&address[0], &buffer[6], 2);
				int payloadLength =
					(((lengthBytes[0] & 0xFF) << 8) |
					 (lengthBytes[1] & 0xFF)
					) & 0xFFFF;
				LOG_INFO("data length: %d", payloadLength);

				if(payloadLength <= 0) {
					//	close (0) or invalid (< 0) packet length
					//	SOCKS client closed relay connection, or an invalid packet got
					//	TODO: close remoteID and bail out
					if(payloadLength == 0) {
						LOG_INFO("TODO: close connection with ID %u.%u.%u.%u:%u",
							address[0], address[1], address[2], address[3],
							port);
					}
					else {
						LOG_INFO("TODO: close connection with ID %u.%u.%u.%u:%u => and bail out due to invalid packet",
							address[0], address[1], address[2], address[3],
							port);
						if(payloadLength < 0) {
							//	invalid packet length; bail out
							end_loop = 1;
						}
					}

					continue;
				}

				//	3. read data of payloadLength
				std::vector<unsigned char> data(payloadLength);
				received = SSL_read(ssl, &data[0], payloadLength);
				LOG_INFO("received: %d", received);
				if(received > 0) {
					std::string strData;
					for(int c = 0; c < received; c++) {
						strData += static_cast<char>(data[c]);
					}
					LOG_INFO("data: %s", strData.c_str());
				}

				//	get or create the remoteID session
			} while(0);
		}
	}
};
int RelayConnectionStarter::relayPort = -1;
std::string RelayConnectionStarter::relayIP = "";
SOCKET RelayConnectionStarter::sockfd = INVALID_SOCKET;

BOOL WINAPI ConsoleHandler(DWORD CtrlType) {
	switch(CtrlType) {
		case CTRL_C_EVENT:
		case CTRL_BREAK_EVENT:
		case CTRL_CLOSE_EVENT:
		case CTRL_LOGOFF_EVENT:
		case CTRL_SHUTDOWN_EVENT:
			RelayConnectionStarter::shutdown();
			return TRUE;
		default:
			return FALSE;
	}
}

void test() {
	PROFILE();
	SetConsoleCtrlHandler(ConsoleHandler, TRUE);
	RelayConnectionStarter::init("193.29.58.141", 19002);
	SetConsoleCtrlHandler(ConsoleHandler, FALSE);
}
} // namespace _2
} // tests

int main() {
	PROFILE();

	// tests::_1::test();
	tests::_2::test();
	return 0;
}
