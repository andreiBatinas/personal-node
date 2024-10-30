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
#if 0
        SSLContext sslContext = SSLContext.getDefault();
        SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
        final SSLSocket socket = (SSLSocket) sslSocketFactory.createSocket();
        socket.setReuseAddress(true);
        socket.setTcpNoDelay(true);
        socket.connect(new InetSocketAddress(relayIP, relayPort), 4000);
        socket.setEnabledProtocols(new String[]{"TLSv1.2"});
        socket.setEnabledCipherSuites(new String[]{
                "TLS_RSA_WITH_AES_256_CBC_SHA",
                "TLS_RSA_WITH_AES_128_CBC_SHA",
                "TLS_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_RSA_WITH_AES_128_GCM_SHA256"
        });
#endif
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
			LOG_INFO("=> inet_pton");
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


			const char* cipher_suites[] = {
				TLS1_RFC_RSA_WITH_AES_256_SHA,
				TLS1_RFC_RSA_WITH_AES_128_SHA,
				TLS1_RFC_RSA_WITH_AES_256_GCM_SHA384,
				TLS1_RFC_RSA_WITH_AES_128_GCM_SHA256
			};
			std::string strCipherSuites = "";
			for (const auto& suite : cipher_suites) {
				if (!strCipherSuites.empty())
					strCipherSuites += ";";
				strCipherSuites += suite;
			}
			LOG_INFO("=> SSL_set_ciphersuites");
			rv = SSL_set_ciphersuites(ssl, 
#if 0
				SSL_TXT_ALL
#else
				strCipherSuites.c_str()
#endif
			);
			LOG_INFO("SSL_set_ciphersuites: %d", rv);

			//	TODO? SSL_set_options

			LOG_INFO("=> SSL_set_fd");
			rv = SSL_set_fd(ssl, (int)sockfd);
			LOG_INFO("SSL_set_fd: %d", rv);

			LOG_INFO("=> SSL_connect");
			rv = SSL_connect(ssl);
			LOG_INFO("SSL_connect: %d", rv);

			//	TODO starts thread to read from servers and send to the relay

			//	read from relay
#if 1
			for(;;) {
				char response[6] = { 0 };
				int rv = recv(sockfd, response, sizeof(response), 0);
				LOG_INFO("recv: %d", rv);
				if(rv > 0) {
					for(int c = 0; c < rv; c++) {
						fprintf(stdout, "%c", response[c]);
					}
					fprintf(stdout, "\n");
					for(int c = 0; c < rv; c++) {
						fprintf(stdout, "%2.2x", response[c]);
					}
					fprintf(stdout, "\n");
				}
				else if(rv < 0)
					break;
			}
#else
			for(;;) {
				char response[6] = { 0 };
				//LOG_INFO("=> SSL_read");
				rv = SSL_read(ssl, response, 6);
				LOG_INFO("SSL_read: %d", rv);
				if(rv > 0) {
					for(int c = 0; c < rv; c++) {
						fprintf(stdout, "%c", response[c]);
					}
					fprintf(stdout, "\n");
					for(int c = 0; c < rv; c++) {
						fprintf(stdout, "%2.2x", response[c]);
					}
					fprintf(stdout, "\n");
				}
				else {
					bool disconnected = false;

					int err = SSL_get_error(ssl, rv);
					switch(err) {
						case SSL_ERROR_NONE:
							LOG_INFO("SSL_get_error: SSL_ERROR_NONE: continue");
							continue;
						case SSL_ERROR_SSL:
							LOG_INFO("SSL_get_error: SSL_ERROR_SSL");
							break;
						case SSL_ERROR_ZERO_RETURN:
							LOG_INFO("SSL_get_error: SSL_ERROR_ZERO_RETURN: disconnected: break");
							disconnected = true;
							break;
						case SSL_ERROR_WANT_READ:
							LOG_INFO("SSL_get_error: SSL_ERROR_WANT_READ");
							{
								int sock = SSL_get_rfd(ssl);
								fd_set fds;
								FD_ZERO(&fds);
								FD_SET(sock, &fds);
								timeval timeout;
								timeout.tv_sec = 0;
								timeout.tv_usec = 500 * 1000;

								err = select(sock + 1, &fds, nullptr, nullptr, &timeout);
								if(err > 0) {
									continue;
								}
								else if(err == 0) {
									//	timeout
									continue;
								}
								else {
									//	error
									disconnected = true;
									break;
								}
							}
							break;
						case SSL_ERROR_WANT_WRITE:
							LOG_INFO("SSL_get_error: SSL_ERROR_WANT_WRITE");
							{
								int sock = SSL_get_rfd(ssl);
								fd_set fds;
								FD_ZERO(&fds);
								FD_SET(sock, &fds);
								timeval timeout;
								timeout.tv_sec = 0;
								timeout.tv_usec = 500 * 1000;

								err = select(sock + 1, &fds, nullptr, nullptr, &timeout);
								if(err > 0) {
									continue;
								}
								else if(err == 0) {
									//	timeout
									continue;
								}
								else {
									//	error
									disconnected = true;
									break;
								}
							}
							break;

						default:
							break;
					}

					if(disconnected)
						break;
				}

				LOG_INFO("read loop done");
			}
#endif

			// SSL_set_fd(ssl)

#if 0
			long timeout = 5;
			LOG_INFO("=> SSL_CTX_set_timeout: %ld seconds", timeout);
			SSL_CTX_set_timeout(ctx, 5);
			LOG_INFO("SSL_CTX_set_timeout: %d", rv);

			LOG_INFO("=> BIO_new_ssl_connect");
			bio = BIO_new_ssl_connect(ctx);
			LOG_INFO("BIO_new_ssl_connect: bio:%p", bio);

			LOG_INFO("=> BIO_get_ssl");
			rv = BIO_get_ssl(bio, &ssl);
			LOG_INFO("BIO_get_ssl => %d: ssl:%p", rv, ssl);

			LOG_INFO("=> SSL_set_mode SSL_MODE_AUTO_RETRY");
			rv = SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
			LOG_INFO("SSL_set_mode SSL_MODE_AUTO_RETRY => %d", rv);

			//LOG_INFO("=> SSL_set_mode SSL_MODE_ASYNC");
			//rv = SSL_set_mode(ssl, SSL_MODE_ASYNC);
			//LOG_INFO("SSL_set_mode SSL_MODE_ASYNC => %d", rv);

			char endpoint[256] = {0};
			snprintf(endpoint, sizeof(endpoint), "%s:%d", relayIP.c_str(), relayPort);
			LOG_INFO("=> BIO_set_conn_hostname: endpoint: %s", endpoint);
			BIO_set_conn_hostname(bio, endpoint);

			LOG_INFO("=> BIO_do_connect");
			rv = BIO_do_connect(bio);
			LOG_INFO("BIO_do_connect => %d", rv);

			LOG_INFO("=> SSL_get_verify_result");
			long verify_flag = SSL_get_verify_result(ssl);
			const char* vferr = X509_verify_cert_error_string(verify_flag);
			LOG_INFO("SSL_get_verify_result => %ld:%s", verify_flag, vferr ? vferr : "N/A");

			//	sample request
#if 0
			LOG_INFO("=> BIO_puts");
			char request[512] = {0};
			snprintf(request, sizeof(request),
				"GET / HTTP/1.1\r\n"
				"Host: %s\r\n"
				"Connection: Close\r\n"
				"\r\n",
				relayIP.c_str()
			);
			rv = BIO_puts(bio, request);
			LOG_INFO("BIO_puts => %d", rv);

			//	response
			for(;;) {
				LOG_INFO("=> BIO_read");
				char response[512] = {0};
				rv = BIO_read(bio, response, sizeof(response));
				LOG_INFO("BIO_read: %d", rv);
				if(rv <= 0)
					break;
				if(rv < sizeof(response))
					response[rv] = '\0';
				LOG_INFO("BIO_read: %s", response);
			}
#endif
			//	read from relay
			LOG_INFO("=> BIO_read");
			char response[6] = {0};
			rv = BIO_read(bio, response, sizeof(response));
			LOG_INFO("BIO_read: %d", rv);
			LOG_INFO("BIO_read: %2.2x%2.2x%2.2x%2.2x%2.2x%2.2x",
				response[0], response[1], response[2],
				response[3], response[4], response[5]);

#endif

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
		//LOG_INFO("=> BIO_free_all: bio:%p", bio);
		//if(bio != nullptr)
		//	BIO_free_all(bio);

		LOG_INFO("=> EVP_cleanup");
		EVP_cleanup();

		LOG_INFO("=> WSACleanup");
		rv = WSACleanup();
		LOG_INFO("WSACleanup: %d");

		LOG_INFO("DONE");
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
