#include "logger.h"
#include <cstdio>
#include <thread>

int logger::level_ = logger::LVL_UNKNOWN;

void logger::setLevel(int level) {
	if(level >= LVL_FIRST && level <= LVL_LAST) {
		logger::level_ = level;
	}
}

void logger::vlog(const char* level, const char* fmt, va_list ap) {
	char buf[512] = {0};
	vsnprintf(buf, sizeof(buf), fmt, ap);
	fprintf(stdout, "[%5u:%5u] %s %s\n", _getpid(), _Thrd_id(), level, buf);
}

void __cdecl logger::log(const char* level, const char* fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	logger::vlog(level, fmt, ap);
	va_end(ap);
}

void logger::vlog(LEVEL level, const char* fmt, va_list ap) {
	const char* s_level = nullptr;
	switch(level) {
		case logger::LVL_ERROR:
			s_level = "ERROR";
			break;
		case logger::LVL_WARNING:
			s_level = "WARN ";
			break;
		case logger::LVL_INFO:
			s_level = "INFO ";
			break;
		case logger::LVL_TRACE:
			s_level = "TRACE";
			break;
		default:
			break;
	}
	if(s_level == nullptr)
		return;
	va_list apc;
	va_copy(apc, ap);
	logger::vlog(s_level, fmt, apc);
	va_end(apc);
}

void __cdecl logger::error(const char* fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	logger::vlog(logger::LVL_ERROR, fmt, ap);
	va_end(ap);
}

void __cdecl logger::warning(const char* fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	logger::vlog(logger::LVL_WARNING, fmt, ap);
	va_end(ap);
}

void __cdecl logger::info(const char* fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	logger::vlog(logger::LVL_INFO, fmt, ap);
	va_end(ap);
}

void __cdecl logger::trace(const char* fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	logger::vlog(logger::LVL_TRACE, fmt, ap);
	va_end(ap);
}

logger_profile_function::logger_profile_function(const char* function)
	: function_(function) {
	LOG_TRACE("[%s] ==>", function_.c_str());
}

logger_profile_function::~logger_profile_function() {
	LOG_TRACE("<== [%s]", function_.c_str());
}
