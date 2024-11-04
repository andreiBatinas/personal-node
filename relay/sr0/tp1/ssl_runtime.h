#pragma once

#include <atomic>

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
	static int init();
	static void uninit();
};
