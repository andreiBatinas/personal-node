#include "logger.h"
#include <cstdio>
#include <thread>

void logger::vlog(const char* level, const char* fmt, va_list ap) {
	char buf[512] = {0};
	vsnprintf(buf, sizeof(buf), fmt, ap);
	fprintf(stdout, "[%u:%u] %s %s\n", _getpid(), _Thrd_id(), level, buf);
}

void __cdecl logger::log(const char* level, const char* fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	logger::vlog(level, fmt, ap);
	va_end(ap);
}

logger_profile_function::logger_profile_function(const char* function)
	: function_(function) {
	LOG_INFO("[%s] ==>", function_.c_str());
}

logger_profile_function::~logger_profile_function() {
	LOG_INFO("[%s] <==", function_.c_str());
}
