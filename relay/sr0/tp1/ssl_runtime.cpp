#include "ssl_runtime.h"

#include "openssl/err.h"
#include "logger.h"

SSLRuntime* SSLRuntime::self_ = nullptr;
std::mutex SSLRuntime::mutex_;

SSLRuntime::SSLRuntime() {
}

SSLRuntime::~SSLRuntime() {
}

int SSLRuntime::init_() {
	PROFILE();

	int rv = SSL_library_init();
	LOG_INFO("[" __FUNCTION__ "] %s => %d", "SSL_library_init", rv);
	if(rv == 0) {
		rv_ = ERR_peek_last_error();
		LOG_ERROR("SSL_library_init: fail: %d", rv_);
		return -1;
	}

	rv = SSL_load_error_strings();
	LOG_INFO("%s => %d", "SSL_load_error_strings", rv);
	if(rv == 0) {
		rv_ = ERR_peek_last_error();
		LOG_ERROR("SSL_load_error_strings: fail: %d", rv_);
		return -1;
	}

	rv = ERR_load_BIO_strings();
	LOG_INFO("%s => %d", "ERR_load_BIO_strings", rv);
	if(rv == 0) {
		rv_ = ERR_peek_last_error();
		LOG_ERROR("ERR_load_BIO_strings: fail: %d", rv_);
		return -1;
	}

	rv = ERR_load_crypto_strings();
	LOG_INFO("%s => %d", "ERR_load_crypto_strings", rv);
	if(rv == 0) {
		rv_ = ERR_peek_last_error();
		LOG_ERROR("ERR_load_crypto_strings: fail: %d", rv_);
		return -1;
	}

	rv_ = 0;

	return 0;
}

void SSLRuntime::uninit_() {
	ERR_free_strings();

	SSLRuntime::self_ = nullptr;
	delete this;
}

SSLRuntime* SSLRuntime::self() {
	PROFILE();

	if (!SSLRuntime::self_) {
		SSLRuntime::self_ = new SSLRuntime;
	}
	return SSLRuntime::self_;
}

int SSLRuntime::initialized() {
	std::lock_guard<std::mutex> guard(mutex_);
	return SSLRuntime::self_ != nullptr;
}

int SSLRuntime::init() {
	PROFILE();

	std::lock_guard<std::mutex> guard(mutex_);
	SSLRuntime* ssl_runtime = SSLRuntime::self();
	if (ssl_runtime == nullptr) {
		return -ENOMEM;
	}
	if (ssl_runtime->init_() != 0) {
		SSLRuntime::self_->uninit_();
		return -EFAULT;
	}
	return 0;
}

int SSLRuntime::uninit() {
	PROFILE();

	std::lock_guard<std::mutex> guard(mutex_);
	if (SSLRuntime::self_ != nullptr) {
		SSLRuntime::self_->uninit_();
	}
	return 0;
}

int SSLRuntime::last_error() {
	return ERR_peek_last_error();
}
