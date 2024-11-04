#pragma once

#include <cstdarg>
#include <string>

struct logger {
public:
	enum LEVEL {
		LVL_UNKNOWN = -1,
		LVL_ERROR = 0,
		LVL_WARNING = 1,
		LVL_INFO = 2,
		LVL_TRACE = 3,

		LVL_FIRST = LVL_ERROR,
		LVL_LAST = LVL_TRACE,
	};
private:
	static int level_;
public:
	static void setLevel(int level);

	static void vlog(const char* level, const char* fmt, va_list ap);
	static void vlog(LEVEL level, const char* fmt, va_list ap);
	
	static void __cdecl log(const char* level, const char* fmt, ...);
	static void __cdecl error(const char* fmt, ...);
	static void __cdecl warning(const char* fmt, ...);
	static void __cdecl info(const char* fmt, ...);
	static void __cdecl trace(const char* fmt, ...);
};
#define LOG_ERROR(fmt, ...)    logger::error(fmt, __VA_ARGS__)
#define LOG_WARNING(fmt, ...)  logger::warning(fmt, __VA_ARGS__)
#define LOG_INFO(fmt, ...)     logger::info(fmt, __VA_ARGS__)
#define LOG_TRACE(fmt, ...)    logger::trace(fmt, __VA_ARGS__)

class logger_profile_function {
private:
	std::string function_;
public:
	logger_profile_function(const char* function);
	~logger_profile_function();
};
#define PROFILE()       logger_profile_function __logger_profile_function__(__FUNCTION__)
