#include "tp1.h"

#if defined(WIN32)
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#endif
#include <cassert>
#include <memory>
#include <thread>

#include "openssl/ssl.h"
#include "openssl/err.h"
#include "logger.h"
#include "socket.h"
#include "sockets_runtime.h"
#include "ssl_connection.h"
#include "ssl_runtime.h"
#include "utils.h"
#if 0
#include "relay_api.h"
#endif

namespace tests {

namespace _2 {


class RelayConnectionStarter {
private:
	static int relayPort;
	static std::string relayIP;
	static Socket sockfd;
public:
	static void shutdown() {
		PROFILE();

		sockfd.shutdown();
	}
	static void init(const std::string& relayIP, int relayPort) {
		RelayConnectionStarter::relayIP = relayIP;
		RelayConnectionStarter::relayPort = relayPort;

		openRelayConnection();
	}

	static void openRelayConnection() {
		int rv;

		do {
			if(relayIP.empty() || relayPort <= 0)
				break;

			SocketsRuntime::init();

			//	plain socket
			LOG_TRACE("=> socket");
			sockfd.create(AF_INET, SOCK_STREAM, 0);
#ifdef WIN32
			LOG_TRACE("sockfd: %llu", sockfd.handle());
#else
			LOG_TRACE("sockfd: %d", sockfd.handle());
#endif

			LOG_TRACE("=> setsockopt SO_REUSEADDR");
			sockfd.setReuseAddr(true);

			LOG_TRACE("=> setsockopt TCP_NODELAY");
			sockfd.setTcpNoDelay(true);
			
			LOG_TRACE("=> connect");
			if(!sockfd.connect(relayIP, relayPort)) {
				LOG_INFO("connect: %d", sockfd.last_result());
				break;
			}

			//	init SSL runtime
			rv = SSLRuntime::init();
			LOG_TRACE("SSLRuntime::init() => %d", rv);

			//	context
			SSLConnection ssl_connection;
			if(!ssl_connection.init(TLS1_2_VERSION /*, TLS1_3_VERSION*/)) {
				LOG_ERROR("ssl_connection.init(TLS1_2_VERSION) fail:%d error:%d",
					ssl_connection.last_result(), ssl_connection.last_error());
				break;
			}
			LOG_TRACE("ssl_connection.init(TLS1_2_VERSION) => %d",
				ssl_connection.last_result());

			//	associate with opened relay socket
			if(!ssl_connection.setSocket(sockfd)) {
				LOG_INFO("ssl_connection.setSocket() => %d", rv);
				break;
			}


			LOG_INFO("=> SSL_connect");
			if(!ssl_connection.connect()) {
				LOG_ERROR("SSL_connect fail: %d: error:%d",
					ssl_connection.last_result(), ssl_connection.last_error());
				break;
			}

			//	TODO starts thread to read from servers and send to the relay
			std::thread tlsThread = std::move(
				std::thread([&]() -> void {
					tests::_2::RelayConnectionStarter::RunTlsIO(
						ssl_connection, RelayConnectionStarter::sockfd);
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
		LOG_INFO("=> sockfd.close()");
		sockfd.close();

		LOG_INFO("=> SSLRuntime::uninit()");
		SSLRuntime::uninit();

		LOG_INFO("=> SocketsRuntime::uninit()");
		SocketsRuntime::uninit();

		LOG_INFO("DONE");
	}

	static void RunTlsIO(const SSLConnection& ssl_connection, const Socket& sockfd) {
		PROFILE();

		//	TODO starts thread that reads data from the destination servers and sends it back to the relay

		//	read from relay
		int end_loop = 0;
		for(; end_loop == 0; ) {
			//	readFromRelay()
			do {
				//	1. session ID: 6 bytes
				unsigned char session[Utils::BUFSIZ_SESSION] = {0};
				if(!Utils::readSession(ssl_connection, session, Utils::BUFSIZ_SESSION)) {
					LOG_INFO("session: invalid packet or connection closed");
					end_loop = 1;
					break;
				}

				unsigned char address[Utils::BUFSIZ_IPV4] = {0};
				unsigned short port = 0;
				if(!Utils::extractEndpoint(session, address, sizeof(address),
					&port)) {
					LOG_ERROR("could not read endpoint");
					end_loop = 1;
					break;
				}
				LOG_INFO("endpoint: IP:%u.%u.%u.%u port:%u",
					address[0], address[1], address[2], address[3],
					port);


				//	6 bytes
				//		4 bytes [0..3] IPv4 address
				//		2 bytes [4..5] port
				std::string remoteID = Utils::extractRemoteID(session);
				if(remoteID.empty()) {
					LOG_INFO("could not extract remoteID from session");
					end_loop = 1;
					break;
				}

				//	2. data length: 2 bytes
				int payloadLength = Utils::readDataLength(ssl_connection);
				LOG_INFO("data length: %d", payloadLength);
				if(payloadLength < 0) {
					LOG_INFO("could not read data length");
					break;
				}

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
				std::unique_ptr<unsigned char[]> data =
					std::make_unique<unsigned char[]>(payloadLength);
				if(!Utils::readData(ssl_connection, &data[0], payloadLength)) {
					LOG_INFO("could not read data length");
					break;
				}
				LOG_INFO("received data length: %d", payloadLength);
#if 0
				std::string strData;
				for(int c = 0; c < payloadLength; c++) {
					strData += static_cast<char>(data[c]);
				}
				LOG_INFO("data: %s", strData.c_str());
#endif

				//	get or create the remoteID session
			} while(0);
		}
	}
};
int RelayConnectionStarter::relayPort = -1;
std::string RelayConnectionStarter::relayIP = "";
Socket RelayConnectionStarter::sockfd;

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

int main(int argc, char** argv) {
	PROFILE();

#ifdef WIN32
#ifdef _DEBUG
	bool break_on_start = false;
	for(int c = 1; c < argc; ++c) {
		if(strstr(argv[c], "--break-on-startup")) {
			break_on_start = true;
			break;
		}
	}
	if(break_on_start) {
		while(!IsDebuggerPresent())
			;
	}
#endif // _DEBUG
#endif // WIN32

	// tests::_1::test();
	tests::_2::test();
	return 0;
}
