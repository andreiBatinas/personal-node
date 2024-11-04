#pragma once

#include <mutex>
#include "openssl/ssl.h"
#include "openssl/err.h"

class SSLRuntime {
private:
	static SSLRuntime* self_;
	static std::mutex mutex_;

	int rv_ = 0;

private:
	SSLRuntime();
	~SSLRuntime();
private:
	SSLRuntime(const SSLRuntime&) = delete;
	SSLRuntime(SSLRuntime&&) = delete;
	SSLRuntime& operator=(const SSLRuntime&) = delete;
	SSLRuntime&& operator=(SSLRuntime&&) = delete;

private:
	int init_();
	void uninit_();

public:
	static SSLRuntime* self();
	static int initialized();
	static int init();
	static int uninit();
	static int last_error();
};
