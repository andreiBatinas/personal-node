#include "ssl_runtime.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "logger.h"
#include <cassert>

std::atomic<int> SSLRuntime::ref_;

int SSLRuntime::init() {
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

void SSLRuntime::uninit() {
	PROFILE();

	if(SSLRuntime::ref_.fetch_sub(1) > 0) {
		return;
	}

	LOG_TRACE("=> EVP_cleanup");
	EVP_cleanup();
}
