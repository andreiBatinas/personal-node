#include "ssl_connection.h"
#include "openssl/err.h"
#include "logger.h"
#include <cassert>

SSLConnection::SSLConnection() {
}

SSLConnection::SSLConnection(long tls_min_version, long tls_max_version) {
	init(tls_min_version, tls_max_version);
}

SSLConnection::~SSLConnection() {
}

int SSLConnection::init(long tls_min_version, long tls_max_version) {
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
		//	TODO for some reason SSL_set_min_proto_version returns 0
		//	for TLS1_2_VERSION and OpenSSL 1.1.1n
		LOG_TRACE("SSL_set_min_proto_version: %d", rv_);

		if(tls_max_version != -1) {
			LOG_TRACE("=> SSL_set_max_proto_version");
			rv_ = SSL_set_max_proto_version(ssl_, tls_max_version);
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

bool SSLConnection::setSocket(const Socket& socket) {
	if(!socket)
		return false;
	LOG_TRACE("=> SSL_set_fd");
	int rv = SSL_set_fd(ssl_, socket.handle());
	LOG_TRACE("SSL_set_fd: %d", rv);
	return rv == 1;
}

bool SSLConnection::connect() {
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

SSLConnection::operator SSL*() const {
	return ssl_;
}

int SSLConnection::last_result() const {
	return rv_;
}

int SSLConnection::last_error() {
#ifdef WIN32
	return WSAGetLastError();
#else
	return errno;
#endif
}
