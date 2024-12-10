#include "tp1.h"

#if defined(WIN32)
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#endif
#include <cassert>
#include <iostream>
#include <memory>
#include <thread>

#include "openssl/ssl.h"
#include "openssl/err.h"
#include "event.h"
#include "logger.h"
#include "scoped_destruct.h"
#include "socket.h"
#include "sockets_runtime.h"
#include "ssl_connection.h"
#include "ssl_runtime.h"
#include "utils.h"
#include "relay_api.h"

namespace tests {

namespace _2 {

class RelayConnectionStarter {
private:
	static int relayPort;
	static std::string relayIP;
	static Socket sockfd;
public:
	static void shutdown() {
		PROFILE();

		sockfd.shutdown();
	}
	static void init(const std::string& relayIP, int relayPort) {
		RelayConnectionStarter::relayIP = relayIP;
		RelayConnectionStarter::relayPort = relayPort;

		openRelayConnection();
	}

	static void openRelayConnection() {
		int rv;

		do {
			if(relayIP.empty() || relayPort <= 0)
				break;

			SocketsRuntime::init();

			//	plain socket
			LOG_TRACE("=> socket");
			sockfd.create(AF_INET, SOCK_STREAM, 0);
#ifdef WIN32
			LOG_TRACE("sockfd: %llu", sockfd.handle());
#else
			LOG_TRACE("sockfd: %d", sockfd.handle());
#endif

			LOG_TRACE("=> setsockopt SO_REUSEADDR");
			sockfd.setReuseAddr(true);

			LOG_TRACE("=> setsockopt TCP_NODELAY");
			sockfd.setTcpNoDelay(true);
			
			LOG_TRACE("=> connect");
			if(!sockfd.connect(relayIP, relayPort)) {
				LOG_INFO("connect: %d", sockfd.last_result());
				break;
			}

			//	init SSL runtime
			rv = SSLRuntime::init();
			LOG_TRACE("SSLRuntime::init() => %d", rv);

			//	context
			SSLConnection ssl_connection;
			if(!ssl_connection.init(TLS1_2_VERSION /*, TLS1_3_VERSION*/)) {
				LOG_ERROR("ssl_connection.init(TLS1_2_VERSION) fail:%d error:%d",
					ssl_connection.last_result(), ssl_connection.last_error());
				break;
			}
			LOG_TRACE("ssl_connection.init(TLS1_2_VERSION) => %d",
				ssl_connection.last_result());

			//	associate with opened relay socket
			if(!ssl_connection.setSocket(sockfd)) {
				LOG_INFO("ssl_connection.setSocket() => %d", rv);
				break;
			}


			LOG_INFO("=> SSL_connect");
			if(!ssl_connection.connect()) {
				LOG_ERROR("SSL_connect fail: %d: error:%d",
					ssl_connection.last_result(), ssl_connection.last_error());
				break;
			}

			//	TODO starts thread to read from servers and send to the relay
			std::thread tlsThread = std::move(
				std::thread([&]() -> void {
					tests::_2::RelayConnectionStarter::RunTlsIO(
						ssl_connection, RelayConnectionStarter::sockfd);
					}));
			LOG_INFO("[" __FUNCTION__ "] => tlsThread: %p", tlsThread.native_handle());
			if(tlsThread.native_handle() == nullptr) {
				rv = -ENOEXEC;
				LOG_INFO("[" __FUNCTION__ "] => tlsThread_ fail: %d", errno);
			}
			else {
				LOG_INFO("[" __FUNCTION__ "] => %s", "tlsThread_.join()");
				tlsThread.join();
				LOG_INFO("[" __FUNCTION__ "] => %s done", "tlsThread_.join()");
			}
		} while(0);

		//	cleanup
		LOG_INFO("=> sockfd.close()");
		sockfd.close();

		LOG_INFO("=> SSLRuntime::uninit()");
		SSLRuntime::uninit();

		LOG_INFO("=> SocketsRuntime::uninit()");
		SocketsRuntime::uninit();

		LOG_INFO("DONE");
	}

	static void RunTlsIO(const SSLConnection& ssl_connection, const Socket& sockfd) {
		PROFILE();

		//	TODO starts thread that reads data from the destination servers and sends it back to the relay

		//	read from relay
		int end_loop = 0;
		for(; end_loop == 0; ) {
			//	readFromRelay()
			do {
				//	1. session ID: 6 bytes
				unsigned char session[Utils::BUFSIZ_SESSION] = {0};
				if(!Utils::readSession(ssl_connection, session, Utils::BUFSIZ_SESSION)) {
					LOG_INFO("session: invalid packet or connection closed");
					end_loop = 1;
					break;
				}

				unsigned char address[Utils::BUFSIZ_IPV4] = {0};
				unsigned short port = 0;
				if(!Utils::extractEndpoint(session, address, sizeof(address),
					&port)) {
					LOG_ERROR("could not read endpoint");
					end_loop = 1;
					break;
				}
				LOG_INFO("endpoint: IP:%u.%u.%u.%u port:%u",
					address[0], address[1], address[2], address[3],
					port);


				//	6 bytes
				//		4 bytes [0..3] IPv4 address
				//		2 bytes [4..5] port
				std::string remoteID = Utils::extractRemoteID(session);
				if(remoteID.empty()) {
					LOG_INFO("could not extract remoteID from session");
					end_loop = 1;
					break;
				}

				//	2. data length: 2 bytes
				int payloadLength = Utils::readDataLength(ssl_connection);
				LOG_INFO("data length: %d", payloadLength);
				if(payloadLength < 0) {
					LOG_INFO("could not read data length");
					break;
				}

				if(payloadLength <= 0) {
					//	close (0) or invalid (< 0) packet length
					//	SOCKS client closed relay connection, or an invalid packet got
					//	TODO: close remoteID and bail out
					if(payloadLength == 0) {
						LOG_INFO("TODO: close connection with ID %u.%u.%u.%u:%u",
							address[0], address[1], address[2], address[3],
							port);
					}
					else {
						LOG_INFO("TODO: close connection with ID %u.%u.%u.%u:%u => and bail out due to invalid packet",
							address[0], address[1], address[2], address[3],
							port);
						if(payloadLength < 0) {
							//	invalid packet length; bail out
							end_loop = 1;
						}
					}

					continue;
				}

				//	3. read data of payloadLength
				std::unique_ptr<unsigned char[]> data =
					std::make_unique<unsigned char[]>(payloadLength);
				if(!Utils::readData(ssl_connection, &data[0], payloadLength)) {
					LOG_INFO("could not read data length");
					break;
				}
				LOG_INFO("received data length: %d", payloadLength);

				//	get or create the remoteID session
			} while(0);
		}
	}
};
int RelayConnectionStarter::relayPort = -1;
std::string RelayConnectionStarter::relayIP = "";
Socket RelayConnectionStarter::sockfd;

#ifdef WIN32
struct console_handler_t {
private:
	static console_handler_t* self_;
	os::event_t evConsoleCtrlC_;

private:
	console_handler_t() {
		evConsoleCtrlC_.create();
		SetConsoleCtrlHandler(console_handler_t::Handler, TRUE);
	}
	~console_handler_t() {
		SetConsoleCtrlHandler(console_handler_t::Handler, FALSE);
		evConsoleCtrlC_.close();
	}
	static BOOL WINAPI Handler(DWORD CtrlType) {
		switch(CtrlType) {
			case CTRL_C_EVENT:
			case CTRL_BREAK_EVENT:
			case CTRL_CLOSE_EVENT:
			case CTRL_LOGOFF_EVENT:
			case CTRL_SHUTDOWN_EVENT:
				console_handler_t::self_->evConsoleCtrlC_.set();
				RelayConnectionStarter::shutdown();
				return TRUE;
			default:
				return FALSE;
		}
	}
public:
	static void init() {
		if(self_ == nullptr) {
			self_ = new console_handler_t();
		}
	}
	static void uninit() {
		if(self_ != nullptr) {
			delete self_;
			self_ = nullptr;
		}
	}
	static HANDLE ConsoleCtrlCEvent() {
		if(console_handler_t::self_ == nullptr)
			return nullptr;
		return console_handler_t::self_->evConsoleCtrlC_;
	}
	static bool ConsoleStopRequested(HANDLE hStdin) {
		bool stop_requested = false;

		DWORD cin_events = 0;
		if(GetNumberOfConsoleInputEvents(hStdin, &cin_events)) {
			std::vector<INPUT_RECORD> spInBuf(cin_events);
			DWORD cin_events_read = 0;
			if(ReadConsoleInput(hStdin, &spInBuf[0], cin_events, &cin_events_read)) {
				for(DWORD c = 0; c < cin_events; ++c) {
					if(spInBuf[c].EventType == KEY_EVENT) {
						const auto key_event = &spInBuf[c].Event.KeyEvent;
						if(key_event->uChar.AsciiChar == 'q') {
							stop_requested = true;
							break;
						}
						else if(key_event->bKeyDown &&
							(key_event->dwControlKeyState & LEFT_CTRL_PRESSED || 
								key_event->dwControlKeyState & RIGHT_CTRL_PRESSED) &&
							key_event->wVirtualKeyCode == VK_PAUSE) {
							stop_requested = true;
							break;
						}
					}
				}
			}
		}

		return stop_requested;
	}
};
console_handler_t* console_handler_t::self_ = nullptr;
struct scoped_console_handler_t {
	scoped_console_handler_t() {
		console_handler_t::init();
	}
	~scoped_console_handler_t() {
		console_handler_t::uninit();
	}
};
#endif // WIN32


//	host app
struct HostApp {
private:
	std::atomic<int> ref_;
	std::atomic<bool> running_ = false;

public:
	int addRef() {
		int ref = ++ref_;
		if(ref == 1) {
			running_ = true;
		}
		return ref;
	}
	int release() {
		int ref = --ref_;
		if(ref == 0) {
			running_ = false;
		}
		return ref;
	}
	void logv(logger::LEVEL level, const char* fmt, va_list ap) {
		va_list ap2;
		va_copy(ap2, ap);
		logger::vlog(level, fmt, ap2);
		va_end(ap2);
	}
	void __cdecl error(const char* fmt, ...) {
		va_list ap;
		va_start(ap, fmt);
		logger::error(fmt, ap);
		va_end(ap);
	}
	void __cdecl warning(const char* fmt, ...) {
		va_list ap;
		va_start(ap, fmt);
		logger::warning(fmt, ap);
		va_end(ap);
	}
	void __cdecl info(const char* fmt, ...) {
		va_list ap;
		va_start(ap, fmt);
		logger::info(fmt, ap);
		va_end(ap);
	}
	void __cdecl trace(const char* fmt, ...) {
		va_list ap;
		va_start(ap, fmt);
		logger::trace(fmt, ap);
		va_end(ap);
	}
	bool running() const {
		return running_;
	}
	void stop() {
		running_ = false;
	}

	static void check_break_on_startup(int argc, char** argv) {
#ifdef WIN32
#ifdef _DEBUG
	bool break_on_start = false;
	for(int c = 1; c < argc; ++c) {
		if(strstr(argv[c], "--break-on-startup")) {
			break_on_start = true;
			break;
		}
	}
	if(break_on_start) {
		while(!IsDebuggerPresent())
			;
	}
#endif // _DEBUG
#endif // WIN32
	}
} g_tester;

//	C interface
static int relay_host_application__addRef(struct relay_host_application_t* host) {
	if(host == nullptr)
		return -ENOENT;
	return g_tester.addRef();
}
static int relay_host_application__release(struct relay_host_application_t* host) {
	if(host == nullptr)
		return -ENOENT;
	return g_tester.release();
}
static void __cdecl relay_host_application__log(struct relay_host_application_t* host,
	logger::LEVEL level, const char* fmt, ...) {
	if(host == nullptr)
		return;

	va_list ap;
	va_start(ap, fmt);
	g_tester.logv(level, fmt, ap);
	va_end(ap);
}
static void __cdecl relay_host_application__error(struct relay_host_application_t* host,
	const char* fmt, ...) {
	if(host == nullptr)
		return;

	va_list ap;
	va_start(ap, fmt);
	g_tester.error(fmt, ap);
	va_end(ap);
}
static void __cdecl relay_host_application__warning(struct relay_host_application_t* host,
	const char* fmt, ...) {
	if(host == nullptr)
		return;

	va_list ap;
	va_start(ap, fmt);
	g_tester.warning(fmt, ap);
	va_end(ap);
}
static void __cdecl relay_host_application__info(struct relay_host_application_t* host,
	const char* fmt, ...) {
	if(host == nullptr)
		return;

	va_list ap;
	va_start(ap, fmt);
	g_tester.info(fmt, ap);
	va_end(ap);
}
static void __cdecl relay_host_application__trace(struct relay_host_application_t* host,
	const char* fmt, ...) {
	if(host == nullptr)
		return;

	va_list ap;
	va_start(ap, fmt);
	g_tester.trace(fmt, ap);
	va_end(ap);
}

struct relay_host_application_t tester = {
	&relay_host_application__addRef,
	&relay_host_application__release,
	&relay_host_application__log,
	&relay_host_application__error,
	&relay_host_application__warning,
	&relay_host_application__info,
	&relay_host_application__trace,
};

void test(int argc, char** argv) {
	PROFILE();

	HostApp::check_break_on_startup(argc, argv);

#ifdef WIN32
	scoped_console_handler_t console_handler;
#endif

	const char* relayIP = "193.29.58.141";
	int relayPort = 19002;

#if 0
	RelayConnectionStarter::init(relayIP, relayPort);
#else

	int rv = 0;
	do {
		LOG_TRACE("=> Relay_SetHostApp");
		rv = Relay_SetHostApp(&tester);

		rv = Relay_Init(RELAY_INIT_FLAG_SOCKETS | RELAY_INIT_FLAG_SSL);
		if(rv < 0) {
			break;
		}

		struct relay_connection_t* relay = nullptr;
		rv = RelayConnection_Create(&relay, relayIP, relayPort);
		if(rv == 0) {
			rv = RelayConnection_Start(relay);

			LOG_TRACE("press 'q' or Ctrl/C to exit");
			//bool end_loop = false;
			for(;;) {
				if(!g_tester.running())
					break;

				HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
				HANDLE evConsoleCtrlC = console_handler_t::ConsoleCtrlCEvent();
				HANDLE waitables[2] = {
					hStdin,
					evConsoleCtrlC
				};
				DWORD waitables_count = evConsoleCtrlC != nullptr ? 2 : 1;
				DWORD wait = WaitForMultipleObjects(waitables_count, &waitables[0],
					FALSE, INFINITE);
				if(wait == WAIT_OBJECT_0) {
					if(console_handler_t::ConsoleStopRequested(hStdin)) {
						g_tester.stop();
						break;
					}
				}
				else if(wait == WAIT_OBJECT_0 + 1) {
					//	console break
					g_tester.stop();
					break;
				}
				else {
					LOG_TRACE("WaitForMultipleObjects: %lu", GetLastError());
				}
			}

			RelayConnection_Stop(relay);
			RelayConnection_Destroy(relay);
		}

		Relay_Shutdown();
		Relay_SetHostApp(nullptr);
	} while(0);
#endif

}
} // namespace _2
} // tests

int main(int argc, char** argv) {
	PROFILE();

	tests::_2::test(argc, argv);
	return 0;
}
