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
#if 0
#include "relay_api.h"
#include "scoped_destruct.h"
#include "sockets_runtime.h"
#include "ssl_runtime.h"
#else
#include "openssl/ssl.h"
#include "openssl/err.h"
#endif

namespace tests {
#if 0
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
#endif

namespace Utils {

int readExactly(SSL* ssl, unsigned char* bytes, int size) {
	if(ssl == nullptr || bytes == nullptr || size <= 0) {
		return false;
	}
	int received = SSL_read(ssl, bytes, size);
	LOG_TRACE("received: %d", received);
	return received;
}

//	session ID: 6 bytes
//		4 bytes [0..3] IPv4 address
//		2 bytes [4..5] port
constexpr size_t BUFSIZ_SESSION = 6;
bool readSession(SSL* ssl, unsigned char* session, int size) {
	if(ssl == nullptr || session == nullptr || size != BUFSIZ_SESSION)
		return false;
	memset(&session[0], 0, size);
	if(Utils::readExactly(ssl, session, size) != BUFSIZ_SESSION) {
		LOG_ERROR("session: invalid packet or connection closed");
		return false;
	}
	return true;
}

constexpr size_t BUFSIZ_IPV4 = 4;
bool extractEndpoint(unsigned char session[BUFSIZ_SESSION],
	unsigned char* address, int address_size,
	unsigned short* port) {
	if(address == nullptr || address_size != BUFSIZ_IPV4 || port == nullptr)
		return false;
	memcpy(&address[0], &session[0], BUFSIZ_IPV4);
	*port = ((session[4] & 0xFF) << 8) | (session[5] & 0xFF);
	return true;
}

std::string extractRemoteID(unsigned char session[BUFSIZ_SESSION]) {
	unsigned char address[4] = { 0 };
	memcpy(&address[0], &session[0], BUFSIZ_IPV4);

	unsigned short port = ((session[4] & 0xFF) << 8) | (session[5] & 0xFF);

	char buffer[sizeof("xxx.xxx.xxx.xxx:xxxxxx") + 1] = { 0 };
	int n = snprintf(buffer, sizeof(buffer), "%u.%u.%u.%u:%u",
		address[0], address[1], address[2], address[3],
		port);

	if(n <= 0)
		return {};

	return std::string(buffer);
}

//	data length: 2 bytes
constexpr size_t BUFSIZ_DATA_LENGTH = 2;
int readDataLength(SSL* ssl) {
	unsigned char lengthBytes[Utils::BUFSIZ_DATA_LENGTH] = { 0 };
	memset(&lengthBytes[0], 0, sizeof(lengthBytes));
	if(!Utils::readExactly(ssl, lengthBytes, Utils::BUFSIZ_DATA_LENGTH)) {
		LOG_ERROR("could not read data length");
		return -1;
	}
	int payloadLength =
		(((lengthBytes[0] & 0xFF) << 8) |
			(lengthBytes[1] & 0xFF)
			) & 0xFFFF;
	LOG_TRACE("data length: %d", payloadLength);
	return payloadLength;
}

int readData(SSL* ssl, unsigned char* data, int length) {
	if(ssl == nullptr || data == nullptr || length <= 0)
		return false;

	if(Utils::readExactly(ssl, data, length) != length) {
		LOG_WARNING("data: invalid packet or connection closed");
		return false;
	}
	LOG_TRACE("data received: %d", length);
	return true;
}

} // namespace Utils

namespace _2 {

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
	static int init() {
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
	static void uninit() {
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
};
std::atomic<int> SocketsRuntime::ref_;
#ifdef WIN32
WSADATA SocketsRuntime::wsa_ = {0};
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
	Socket() {
	}
	~Socket() {
	}

	int handle() const {
#ifdef WIN32
		if(s_ == INVALID_SOCKET)
			return -1;
		return static_cast<int>(s_);
#else
		return s_;
#endif
	}

	operator bool() const {
		return s_ != INVALID_SOCKET;
	}
	bool operator !() const {
		return s_ == INVALID_SOCKET;
	}

	bool create(int af, int type, int protocol) {
		PROFILE();

		assert(s_ == INVALID_SOCKET);
		af_ = af;
		s_ = socket(af, type, protocol);
		return s_ != INVALID_SOCKET;
	}
	bool connect(const std::string& ip, int port) {
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
	void close() {
		if(!operator bool())
			return;
		rv_ = closesocket(s_);
		LOG_TRACE("closesocket: %d", rv_);
		s_ = INVALID_SOCKET;
	}
	void shutdown() {
		PROFILE();

		if(s_ != INVALID_SOCKET) {
			LOG_TRACE("=> closesocket: sockfd: %d", s_);
			rv_ = closesocket(s_);
			LOG_TRACE("closesocket: %d", rv_);
			s_ = INVALID_SOCKET;
		}
	}

	bool setReuseAddr(bool on) {
		if(s_ == INVALID_SOCKET)
			return false;
		LOG_TRACE("=> setsockopt SO_REUSEADDR");
		int opt = on ? 1 : 0;
		rv_ = setsockopt(s_, SOL_SOCKET, SO_REUSEADDR,
			(const char*)&opt, sizeof(opt));
		LOG_TRACE("setsockopt SO_REUSEADDR: %d", rv_);
		return rv_ == 0;
	}
	bool setTcpNoDelay(bool on) {
		if(s_ == INVALID_SOCKET)
			return false;
		LOG_TRACE("=> setsockopt SO_REUSEADDR");
		int opt = on ? 1 : 0;
		rv_ = setsockopt(s_, IPPROTO_TCP, TCP_NODELAY,
			(const char*)&opt, sizeof(opt));
		LOG_TRACE("setsockopt SO_REUSEADDR: %d", rv_);
		return rv_ == 0;
	}
	int last_result() const {
		return rv_;
	}
	static int last_error() {
#ifdef WIN32
		return WSAGetLastError();
#else
		return errno;
#endif
	}
private:
	Socket(const Socket&) = delete;
	Socket(Socket&&) = delete;

	Socket& operator=(const Socket&) = delete;
	Socket&& operator=(Socket&&) = delete;
};


class SSLRuntime {
private:
	static std::atomic<int> ref_;
private:
	SSLRuntime() = delete;
	SSLRuntime(const SSLRuntime&) = delete;
	SSLRuntime(SSLRuntime&&) = delete;
	~SSLRuntime() = delete;

	SSLRuntime& operator=(const SSLRuntime&) = delete;
	SSLRuntime&& operator=(SSLRuntime&&) = delete;
public:
	static int init() {
		PROFILE();

		if(SSLRuntime::ref_.fetch_add(1) > 1) {
			return 0;
		}

		int rv = SSL_load_error_strings();
		LOG_TRACE("SSL_load_error_strings => %d", rv);
		assert(rv == 1);
		
		rv = ERR_load_BIO_strings();
		LOG_TRACE("ERR_load_BIO_strings => %d", rv);
		assert(rv == 1);
		
		rv = OpenSSL_add_all_algorithms();
		LOG_TRACE("OpenSSL_add_all_algorithms => %d", rv);
		assert(rv == 1);
		
		rv = SSL_library_init();
		LOG_TRACE("SSL_library_init => %d", rv);
		assert(rv == 1);

		return 0;
	}
	static void uninit() {
		PROFILE();

		if(SSLRuntime::ref_.fetch_sub(1) > 0) {
			return;
		}

		LOG_TRACE("=> EVP_cleanup");
		EVP_cleanup();
	}
};
std::atomic<int> SSLRuntime::ref_;

//	TLSv1.2 SSL connection
class SSLConnection {
private:
	SSL_CTX* ctx_ = nullptr;
	SSL* ssl_ = nullptr;
	int rv_ = -1;
	int err_ = 0;
public:
	SSLConnection() {
	}
	SSLConnection(long tls_min_version, long tls_max_version = -1) {
		init(tls_min_version, tls_max_version);
	}
	~SSLConnection() {
	}

	int init(long tls_min_version, long tls_max_version = -1) {
		do {
			if(tls_min_version < TLS1_VERSION) {
				err_ = -EINVAL;
				break;
			}
			if(tls_max_version != -1 && tls_min_version > tls_max_version) {
				err_ = -EINVAL;
				break;
			}

			const SSL_METHOD* method = nullptr;
			switch(tls_min_version) {
				case TLS1_VERSION:
					LOG_TRACE("=> TLSv1_client_method");
					method = TLSv1_client_method();
					LOG_TRACE("TLSv1 method: %p", method);
					break;
				case TLS1_1_VERSION:
					LOG_TRACE("=> TLSv1_1_client_method");
					method = TLSv1_1_client_method();
					LOG_TRACE("TLSv11 method: %p", method);
					break;
				case TLS1_2_VERSION:
					LOG_TRACE("=> TLSv1_2_client_method");
					method = TLSv1_2_client_method();
					LOG_TRACE("TLSv12 method: %p", method);
					break;
				case TLS1_3_VERSION:
					LOG_TRACE("=> TLSv1_3_client_method");
					method = TLS_client_method();
					LOG_TRACE("TLSv13 method: %p", method);
					break;
				default:
					LOG_WARNING("invalid/unknown TLS version: %ld", tls_min_version);
					break;
			}
			if(method == nullptr) {
				err_ = ERR_peek_last_error();
				break;
			}

			LOG_TRACE("=> SSL_CTX_new");
			ctx_ = SSL_CTX_new(method);
			LOG_TRACE("ctx: %p", ctx_);
			if(ctx_ == nullptr) {
				err_ = ERR_peek_last_error();
				break;
			}
#if 0
			LOG_TRACE("=> SSL_CTX_get_min_proto_version");
			int min_proto = SSL_CTX_get_min_proto_version(ctx_);
			LOG_TRACE("SSL_CTX_get_min_proto_version: %x", min_proto);

			LOG_TRACE("=> SSL_CTX_set_min_proto_version");
			rv_ = SSL_CTX_set_min_proto_version(ctx_, tls_min_version);
#if 0
			//	for some reason SSL_CTX_set_min_proto_version fails
			assert(rv_ == 1);
			if(rv_ != 1) {
				err_ = ERR_peek_last_error();
				LOG_ERROR("SSL_set_min_proto_version fail: error: %d", err_);
				break;
			}
#endif
			LOG_TRACE("SSL_CTX_set_min_proto_version: %d", rv_);
#endif

			
#if 0
			long options = 0;
			if(tls_min_version != TLS1_VERSION)
				options |= SSL_OP_NO_TLSv1;
			if(tls_min_version != TLS1_1_VERSION)
				options |= SSL_OP_NO_TLSv1_1;
			if(tls_min_version != TLS1_2_VERSION)
				options |= SSL_OP_NO_TLSv1_2;
			if(tls_min_version != TLS1_3_VERSION)
				options |= SSL_OP_NO_TLSv1_3;
			if(options != 0) {
				LOG_INFO("=> SSL_CTX_clear_options");
				rv = SSL_CTX_clear_options(ctx_, options);
				LOG_INFO("=> SSL_CTX_clear_options: %d", rv);
			}
#endif

			//	ssl
			LOG_TRACE("=> SSL_new");
			ssl_ = SSL_new(ctx_);
			LOG_TRACE("ssl: %p", ssl_);
			if(ssl_ == nullptr) {
				err_ = ERR_peek_last_error();
				break;
			}

			LOG_TRACE("=> SSL_get_min_proto_version");
			int min_proto_ssl = SSL_get_min_proto_version(ssl_);
			LOG_TRACE("SSL_get_min_proto_version: %x", min_proto_ssl);

			LOG_TRACE("=> SSL_set_min_proto_version");
			rv_ = SSL_set_min_proto_version(ssl_, tls_min_version);
#if 0
			assert(rv_ == 1);
			if(rv_ != 1) {
				err_ = ERR_peek_last_error();
				LOG_ERROR("SSL_set_min_proto_version fail: error: %d", err_);
				break;
			}
#endif
			LOG_TRACE("SSL_set_min_proto_version: %d", rv_);

			if(tls_max_version != -1) {
				LOG_TRACE("=> SSL_set_max_proto_version");
				rv_ = SSL_set_max_proto_version(ssl_, TLS1_2_VERSION);
				assert(rv_ == 1);
				if(rv_ != 1) {
					err_ = ERR_peek_last_error();
					LOG_ERROR("SSL_set_max_proto_version fail: error: %d", err_);
					break;
				}
				LOG_TRACE("SSL_set_max_proto_version: %d", rv_);
			}

			LOG_TRACE("=> SSL_set_ciphersuites");
			rv_ = SSL_set_ciphersuites(ssl_,
				TLS1_RFC_RSA_WITH_AES_256_SHA        ":"
				TLS1_RFC_RSA_WITH_AES_128_SHA        ":"
				TLS1_RFC_RSA_WITH_AES_256_GCM_SHA384 ":"
				TLS1_RFC_RSA_WITH_AES_128_GCM_SHA256
			);
			assert(rv_ == 1);
			if(rv_ != 1) {
				err_ = ERR_peek_last_error();
				LOG_ERROR("SSL_set_min_proto_version fail: error: %d", err_);
				break;
			}
			LOG_TRACE("SSL_set_ciphersuites: %d", rv_);

			return true;
		} while(0);
		return false;
	}
	bool setSocket(const Socket& socket) {
		if(!socket)
			return false;
		LOG_TRACE("=> SSL_set_fd");
		int rv = SSL_set_fd(ssl_, socket.handle());
		LOG_TRACE("SSL_set_fd: %d", rv);
		return rv == 1;
	}

	bool connect() {
		if(ssl_ == nullptr)
			return false;
		LOG_TRACE("=> SSL_connect");
		rv_ = SSL_connect(ssl_);
		if(rv_ != 1) {
			err_ = ERR_peek_last_error();
			LOG_ERROR("SSL_connect: fail:%d error:%d", rv_, err_);
		}
		else {
			LOG_TRACE("SSL_connect: %d", rv_);
		}
		return rv_ == 1;
	}

	operator SSL*() const {
		return ssl_;
	}
	int last_result() const {
		return rv_;
	}
	static int last_error() {
#ifdef WIN32
		return WSAGetLastError();
#else
		return errno;
#endif
	}

private:
	SSLConnection(const SSLConnection&) = delete;
	SSLConnection(SSLConnection&&) = delete;
	SSLConnection& operator=(const SSLConnection&) = delete;
	SSLConnection&& operator=(SSLConnection&&) = delete;
};


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

	static void RunTlsIO(const SSLConnection& ssl_connection, SOCKET sockfd) {
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

	// tests::_1::test();
	tests::_2::test();
	return 0;
}
