#include "tp1.h"

class logger {
public:
	static void vlog(const char* level, const char* fmt, va_list ap) {
		char buf[512] = {0};
		vsnprintf(buf, sizeof(buf), fmt, ap);
		fprintf(stdout, "%s %s\n", level, buf);
	}
	static void __cdecl log(const char* level, const char* fmt, ...) {
		va_list ap;
		va_start(ap, fmt);
		vlog(level, fmt, ap);
		va_end(ap);
	}
};
#define INFO(fmt, ...)  logger::log("INFO ", fmt, __VA_ARGS__)
#define ERROR(fmt, ...) logger::log("ERROR", fmt, __VA_ARGS__)

class RelayConnectionStarter {
private:
	int relayPort = -1;
	std::string relayIP;
public:
	RelayConnectionStarter(const std::string& relayIP, int relayPort) 
		: relayIP(relayIP)
		, relayPort(relayPort) {
	}
	void run() {
		//	create SSL socket
	}
};

int main() {
	INFO("Hello CMake");

	RelayConnectionStarter relay("193.29.58.141", 19002);
	relay.run();
	
	return 0;
}
