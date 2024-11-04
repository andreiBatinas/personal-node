#include "relay_starter.h"

#if 0

#include <cassert>
#include "logger.h"
#include "scoped_destruct.h"
#include "sockets_runtime.h"
#include "ssl_runtime.h"

//
//	relay connection
//
RelayConnectionStarter::RelayConnectionStarter(const std::string& relayIP, int relayPort) 
	: relayIP_(relayIP)
	, relayPort_(relayPort) {
	PROFILE();
}

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

bool RelayConnectionStarter::createSslContext() {
	PROFILE();

	int rv;
	do {
		//	create SSL socket over connection socket
		if(method_ != nullptr) {
			rv = -EALREADY;
			break;
		}
		method_ = TLSv1_2_client_method();
		LOG_INFO("[" __FUNCTION__ "] %s => method: %p", "TLSv1_2_client_method", method_);
		if(method_ == nullptr) {
			rv_ = SSLRuntime::last_error();
			LOG_ERROR("[" __FUNCTION__ "] %s fail: %d", "TLSv1_2_client_method", rv_);
			break;
		}

		if(ctx_ != nullptr) {
			rv = -EALREADY;
			break;
		}
		ctx_ = SSL_CTX_new(method_);
		LOG_INFO("[" __FUNCTION__ "] %s => ctx_: %p", "SSL_CTX_new", ctx_);
		if(ctx_ == nullptr) {
			rv_ = SSLRuntime::last_error();
			LOG_ERROR("[" __FUNCTION__ "] %s fail: %d", "SSL_CTX_new", rv_);
			break;
		}

		long ctx_options = SSL_OP_ALL | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;
		SSL_CTX_set_options(ctx_, ctx_options);

		const char* cipher_list[] = {
#if 0
			SSL_TXT_TLSV1,
			SSL_TXT_TLSV1_1,
			SSL_TXT_TLSV1_2,
#else
			SSL_TXT_ALL,
#endif
		};
		std::string strCipherList = "";
		for (const auto& cipher : cipher_list) {
			if (!strCipherList.empty())
				strCipherList += ";";
			strCipherList += cipher;
		}
		rv = SSL_CTX_set_cipher_list(ctx_, "ALL");
		LOG_INFO("[" __FUNCTION__ "] %s => %d", "cipher_list", rv);
		if(rv != 1) {
			rv_ = SSLRuntime::last_error();
			LOG_INFO("[" __FUNCTION__ "] %s fail: %d", "cipher_list", rv_);
			break;
		}

		return true;
	} while (0);

	LOG_INFO("[" __FUNCTION__ "] returning %d", rv_);
	return false;
}

int RelayConnectionStarter::start() {
	PROFILE();

	int rv;
	do {
		if (relayIP_.empty()) {
			rv_ = -EINVAL;
			LOG_ERROR("[" __FUNCTION__ "] fail: %s", "relay IP is empty");
			break;
		}
		if (relayPort_ < 0) {
			rv_ = -EINVAL;
			LOG_ERROR("[" __FUNCTION__ "] fail: %s", "relay port is invalid");
			break;
		}
		LOG_INFO("[" __FUNCTION__ "] destination: %s:%d", relayIP_.c_str(), relayPort_);

		//	SSL runtime
		assert(SSLRuntime::initialized());

		//	create connection socket
		if(!connectSocket()) {
			LOG_ERROR("[" __FUNCTION__ "] %s fail: %d", "connectSocket", rv_);
			break;
		}

		//	create SSL socket over connection socket
		if(!createSslContext()) {
			break;
		}

		ssl_ = SSL_new(ctx_);
		LOG_INFO("[" __FUNCTION__ "] %s => ssl_:%p", "SSL_new", ssl_);
		if (ssl_ == nullptr) {
			rv_ = SSLRuntime::last_error();
			LOG_ERROR("[" __FUNCTION__ "] %s fail: %d", "SSL_new", rv_);
			break;
		}

		rv = SSL_set_min_proto_version(ssl_, TLS1_2_VERSION);
		LOG_INFO("[" __FUNCTION__ "] %s => %d", "SSL_set_min_proto_version", rv);
		if(rv != 1) {
			rv_ = SSLRuntime::last_error();
			LOG_ERROR("[" __FUNCTION__ "] %s fail: %d", "SSL_set_min_proto_version", rv_);
			break;
		}

		// SSL_set_ciphersuites(ssl_, "");

/*
		bioIn_ = BIO_new(BIO_s_mem());
		LOG_INFO("[" __FUNCTION__ "] %s => bioIn_:%p", "BIO_new", bioIn_);
		if (bioIn_ == nullptr) {
			rv_ = SSLRuntime::last_error();
			LOG_ERROR("[" __FUNCTION__ "] %s fail: %d", "BIO_new", rv_);
			break;
		}
		scoped_destruct __free_bioIn(
			[this]() {
				if(bioIn_ != nullptr)
					BIO_free_all(bioIn_);
			});

		bioOut_ = BIO_new(BIO_s_mem());
		LOG_INFO("[" __FUNCTION__ "] %s => bioOut_:%p", "BIO_new", bioIn_);
		if (bioOut_ == nullptr) {
			rv_ = SSLRuntime::last_error();
			LOG_ERROR("[" __FUNCTION__ "] %s fail: %d", "BIO_new", rv_);
			break;
		}
		scoped_destruct __free_bioOut(
			[this]() {
				if(bioOut_ != nullptr)
					BIO_free_all(bioOut_);
			});

		//	pass ownership tp ssl_; SSL_free will release bio's
		LOG_INFO("[" __FUNCTION__ "] => %s", "SSL_set_bio");
		SSL_set_bio(ssl_, bioIn_, bioOut_);
		__free_bioIn.cancel();
		__free_bioOut.cancel();

		LOG_INFO("[" __FUNCTION__ "] => %s", "SSL_set_accept_state");
		SSL_set_accept_state(ssl_);

		//	TLS I/O thread
		tlsThread_ = std::move(
			std::thread([this]() -> void {
				RunTlsIO();
				}));
		LOG_INFO("[" __FUNCTION__ "] => tlsThread_: %p", "tlsThread_", tlsThread_.native_handle());
		if(tlsThread_.native_handle() == nullptr) {
			rv_ = -ENOEXEC;
			LOG_INFO("[" __FUNCTION__ "] => tlsThread_ fail: %d", errno);
			break;
		}
		LOG_INFO("[" __FUNCTION__ "] => %s", "tlsThread_.join()");
		tlsThread_.join();
		LOG_INFO("[" __FUNCTION__ "] => %s done", "tlsThread_.join()");
*/

#if 0
		//	create SSL socket
		if (method_ != nullptr)
			return -EALREADY;
		method_ = TLSv1_2_client_method();
		LOG_INFO("[" __FUNCTION__ "] %s => method: %p", "TLSv1_2_client_method", method_);
		if(method_ == nullptr) {
			rv_ = SSLRuntime::last_error();
			LOG_ERROR("[" __FUNCTION__ "] %s fail: %d", "TLSv1_2_client_method", rv_);
			break;
		}

		if (ctx_ != nullptr)
			return -EALREADY;
		ctx_ = SSL_CTX_new(method_);
		LOG_INFO("[" __FUNCTION__ "] %s => ctx_: %p", "SSL_CTX_new", ctx_);
		if(ctx_ == nullptr) {
			rv_ = SSLRuntime::last_error();
			LOG_ERROR("[" __FUNCTION__ "] %s fail: %d", "SSL_CTX_new", rv_);
			break;
		}

		if (bio_ != nullptr)
			return -EALREADY;
		bio_ = BIO_new_ssl_connect(ctx_);
		LOG_INFO("[" __FUNCTION__ "] %s => bio_: %p", "BIO_new_ssl_connect", bio_);
		if(bio_ == nullptr) {
			rv_ = SSLRuntime::last_error();
			LOG_ERROR("[" __FUNCTION__ "] %s fail: %d", "BIO_new_ssl_connect", rv_);
			break;
		}

		rv_ = BIO_get_ssl(bio_, &ssl);
		LOG_INFO("[" __FUNCTION__ "] %s => ssl:%p %d", "BIO_get_ssl", ssl, rv_);
		if(ssl == nullptr) {
			rv_ = SSLRuntime::last_error();
			LOG_ERROR("[" __FUNCTION__ "] %s fail: %d", "BIO_get_ssl", rv_);
			break;
		}

		rv = SSL_set_min_proto_version(ssl, TLS1_2_VERSION);
		LOG_INFO("[" __FUNCTION__ "] %s => %d", "SSL_set_min_proto_version", rv);
		if(rv != 1) {
			rv_ = SSLRuntime::last_error();
			LOG_ERROR("[" __FUNCTION__ "] %s fail: %d", "SSL_set_min_proto_version", rv_);
			break;
		}

#if 0
		rv = BIO_set_conn_ip_family(bio_, BIO_FAMILY_IPV4);
		LOG_INFO("[" __FUNCTION__ "] %s => %d", "BIO_set_conn_ip_family", rv);
		if(rv != 1) {
			rv_ = SSLRuntime::last_error();
			LOG_ERROR("[" __FUNCTION__ "] %s fail: %d", "BIO_set_conn_ip_family", rv_);
			break;
		}

		rv = BIO_set_conn_hostname(bio_, relayIP_.c_str());
		LOG_INFO("[" __FUNCTION__ "] %s => %d", "BIO_set_conn_port", rv);
		if(rv != 1) {
			rv_ = SSLRuntime::last_error();
			LOG_ERROR("[" __FUNCTION__ "] %s fail: %d", "BIO_set_conn_port", rv_);
			break;
		}

		rv = BIO_set_conn_port(bio_, relayPort_);
		LOG_INFO("[" __FUNCTION__ "] %s => %d", "BIO_set_conn_port", rv);
		if(rv != 1) {
			rv_ = SSLRuntime::last_error();
			LOG_ERROR("[" __FUNCTION__ "] %s fail: %d", "BIO_set_conn_port", rv_);
			break;
		}
#endif

#if 0
		int tcp_socket = socket(AF_INET, SOCK_STREAM, 0);
		LOG_INFO("[" __FUNCTION__ "] %s => %d", "socket", tcp_socket);
		if (tcp_socket < 0) {
#if defined(WIN32)
			rv_ = SocketRuntime::LastError();
#else
			rv_ = errno;
#endif
			LOG_ERROR("[" __FUNCTION__ "] %s fail: %d", "socket", rv_);
			break;
		}
#endif
			
		// SSL_MODE_ASYNC
		// int options = BIO_SOCK_NODELAY | BIO_SOCK_REUSEADDR | 0;
		// int relaySocket = BIO_socket(BIO_FAMILY_IPV4, SOCK_STREAM, IPPROTO_TCP, options);
		// LOG_INFO("[" __FUNCTION__ "] %s => %ld", "BIO_socket", rv);
			
		//ssl_socket = BIO_new_socket(sock, BIO_NOCLOSE);

		//long rv = BIO_do_connect(bio_);
		//LOG_INFO("[" __FUNCTION__ "] %s => %ld", "BIO_do_connect", rv);
		// BIO_socket(BIO_AF_, socket_type, protocol, options);

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
		rv_ = SSL_CTX_set_ciphersuites(ctx_, strCipherSuites.c_str());
		LOG_INFO("[" __FUNCTION__ "] %s => %d", "SSL_CTX_set_ciphersuites", rv);
		if(rv != 1) {
			rv_ = SSLRuntime::last_error();
			LOG_INFO("[" __FUNCTION__ "] %s fail: %d", "SSL_CTX_set_ciphersuites", rv_);
			break;
		}
#endif // #if 0
	} while (0);

	if (ssl_ != nullptr) {
		SSL_shutdown(ssl_);
		SSL_free(ssl_);
		ssl_ = nullptr;

		bioIn_ = nullptr;
		bioOut_ = nullptr;
	}

	LOG_INFO("[" __FUNCTION__ "] => %s: ctx_=%p", "SSL_CTX_free", ctx_);
	if (ctx_ != nullptr) {
		SSL_CTX_free(ctx_);
		ctx_ = nullptr;
	}

	if(sock_ != -1) {
		closesocket(sock_);
		sock_ = -1;
	}

	LOG_INFO("[" __FUNCTION__ "] => %s", "SSLRuntime::uninit()");
	SSLRuntime::uninit();

	LOG_INFO("[" __FUNCTION__ "] returning %d", rv_);
	return rv_;
}

int RelayConnectionStarter::stop() {
	return -1;
}

void RelayConnectionStarter::init(const std::string& relayIP, int relayPort) {
	PROFILE();

	RelayConnectionStarter starter(relayIP, relayPort);
	starter.openRelayConnection();
}

bool RelayConnectionStarter::openRelayConnection() {
	std::thread ioThread = std::move(
		std::thread([this]() -> void {
			RunTlsIO();
			}));
	LOG_INFO("[" __FUNCTION__ "] => tlsThread_: %p", "ioThread", ioThread.native_handle());
	if(ioThread.native_handle() == nullptr) {
		rv_ = -ENOEXEC;
		LOG_INFO("[" __FUNCTION__ "] => tlsThread_ fail: %d", errno);
		return false;
	}
	LOG_INFO("[" __FUNCTION__ "] => %s", "tlsThread_.join()");
	tlsThread_.join();
	LOG_INFO("[" __FUNCTION__ "] => %s done", "tlsThread_.join()");

	return true;
}

bool RelayConnectionStarter::connectSocket() {
	do {
		assert(sock_ != -1);
		if (sock_ == -1) {
			rv_ = -EINVAL;
			break;
		}

		//	create connection socket
		struct addrinfo hint = {0};
		memset(&hint, 0, sizeof(hint));
		hint.ai_family = AF_UNSPEC;
		hint.ai_socktype = SOCK_STREAM;
		hint.ai_protocol = IPPROTO_TCP;
		hint.ai_flags = AI_NUMERICSERV;

		char port[8] = {0};
		snprintf(port, sizeof(port), "%d", relayPort_);

		addrinfo* relay_addrinfo = nullptr;
		scoped_destruct __free_relay_addrinfo(
			[&relay_addrinfo]() {
				SocketsRuntime::free_addrinfo(relay_addrinfo);
			});
		rv_ = SocketsRuntime::get_addrinfo(relayIP_.c_str(), port, &hint, &relay_addrinfo);
		if (rv_ != 0) {
			rv_ = SocketsRuntime::last_error();
			LOG_ERROR("[" __FUNCTION__ "] %s fail: %d", "getaddrinfo", rv_);
			break;
		}
		if (!relay_addrinfo) {
			rv_ = -ENOMEM;
			LOG_ERROR("[" __FUNCTION__ "] %s fail: %d", "getaddrinfo", rv_);
			break;
		}

		socket_t s = socket(AF_UNSPEC, SOCK_STREAM, IPPROTO_TCP);
		LOG_INFO("[" __FUNCTION__ "] %s => %d", "socket", s);
		if (s == INVALID_SOCKET) {
			rv_ = SocketsRuntime::last_error();
			LOG_ERROR("[" __FUNCTION__ "] %s fail: %d", "socket", rv_);
			break;
		}
		scoped_destruct __close_s(
			[&s]() {
				if(s != -1)
					closesocket(s);
			});

		rv_ = connect(s, relay_addrinfo->ai_addr, (int)relay_addrinfo->ai_addrlen);
		if (rv_ == -1) {
			rv_ = SocketsRuntime::last_error();
			LOG_ERROR("[" __FUNCTION__ "] %s fail: %d", "socket", rv_);
			break;
		}
		__close_s.cancel();

		sock_ = s;
		return true;
	} while (0);

	return false;
}

void RelayConnectionStarter::RunTlsIO() {
	// auto relayer = std::enable_shared_from_this();
}

#endif
