#pragma once

#include <cstdarg>
#include <string>

class logger {
public:
	static void vlog(const char* level, const char* fmt, va_list ap);
	static void __cdecl log(const char* level, const char* fmt, ...);
};
#define LOG_INFO(fmt, ...)  logger::log("INFO ", fmt, __VA_ARGS__)
#define LOG_ERROR(fmt, ...) logger::log("ERROR", fmt, __VA_ARGS__)

class logger_profile_function {
private:
	std::string function_;
public:
	logger_profile_function(const char* function);
	~logger_profile_function();
};
#define PROFILE()       logger_profile_function __logger_profile_function__(__FUNCTION__)
