#include "relay_api.h"
#include "logger.h"
#include "relay_connection.h"
#include "sockets_runtime.h"
#include "ssl_runtime.h"
#include <cassert>
#include <map>
#include <mutex>

std::mutex g_mtxApp;
struct relay_host_application_t* g_hostApp = nullptr;

static std::atomic<uint32_t> g_InitFlags = RELAY_INIT_FLAG_NOT_INIT;

std::mutex g_mtxConnections;
static std::map<uint32_t, relay_connection_t*> g_Connections;

//
//	C-like API interface
//
static constexpr int OBJ_INDEX_INVALID = 0xFFFFFFFE;
static constexpr int OBJ_INDEX_MAX = 0x0000FFFF;

static constexpr int OBJID_NONE = 0x0;
static constexpr int OBJID_RELAY_CONNECTION = 0x1;

int Relay_Init(
	uint32_t flags) {
	PROFILE();

	if(g_hostApp != nullptr)
		g_hostApp->log(g_hostApp, logger::LVL_TRACE, "=> Relay_Init");

	int rv = 0;
	do {
		if(flags == RELAY_INIT_FLAG_NOT_INIT) {
			rv = -EINVAL;
			break;
		}

		bool need_sockets = flags & RELAY_INIT_FLAG_SOCKETS;
		bool need_ssl = flags & RELAY_INIT_FLAG_SSL;
		if(!(need_sockets || need_ssl)) {
			//	nothing to do
			g_InitFlags.exchange(RELAY_INIT_FLAG_NONE);
			rv = 0;
			break;
		}

		uint32_t actual_flags = flags;
		uint32_t current_flags = RELAY_INIT_FLAG_NOT_INIT;
		if(!g_InitFlags.compare_exchange_strong(current_flags, actual_flags)) {
			//	already equal
			rv = EALREADY;
			break;
		}

		if(need_sockets) {
			rv = SocketsRuntime::init();
			LOG_TRACE("SocketsRuntime::init() => %d", rv);
			if(rv != 0) {
				break;
			}
		}

		if(need_ssl) {
			//	init SSL runtime
			rv = SSLRuntime::init();
			if(g_hostApp != nullptr)
				g_hostApp->trace(g_hostApp, "SSLRuntime::init() => %d", rv);
			if(rv != 0) {
				break;
			}
		}

		rv = 0;
	} while(0);

	if(g_hostApp != nullptr)
		g_hostApp->log(g_hostApp, logger::LVL_TRACE, "Relay_Init: %d", rv);
	return rv;
}

int Relay_Shutdown(
	void) {
	PROFILE();

	uint32_t flags = g_InitFlags.exchange(RELAY_INIT_FLAG_NOT_INIT);

	if(flags & RELAY_INIT_FLAG_SSL) {
		if(g_hostApp != nullptr)
			g_hostApp->trace(g_hostApp, "=> SSLRuntime::uninit()");
		SSLRuntime::uninit();
	}

	if(flags & RELAY_INIT_FLAG_SOCKETS) {
		if(g_hostApp != nullptr)
			g_hostApp->trace(g_hostApp, "=> SocketsRuntime::uninit()");
		SocketsRuntime::uninit();
	}

	return 0;
}

int Relay_SetHostApp(struct relay_host_application_t* host) {
	if(g_hostApp != nullptr)
		g_hostApp->trace(g_hostApp, "=> Relay_SetHostApp");

	std::lock_guard<std::mutex> lock(g_mtxApp);
	if(g_hostApp != nullptr)
		g_hostApp->release(g_hostApp);

	g_hostApp = host;
	if(g_hostApp != nullptr) {
		g_hostApp->addRef(g_hostApp);
	}

	if(g_hostApp != nullptr)
		g_hostApp->trace(g_hostApp, "Relay_SetHostApp: %d", 0);

	return 0;
}

int RelayConnection_Create(
	relay_connection_t** obj,
	const char* relayIP,
	int relayPort) {
	PROFILE();

	if(g_hostApp != nullptr)
		g_hostApp->trace(g_hostApp, "=> RelayConnection_Create");

	int rv = 0;
	do {
		if(obj == nullptr) {
			rv = -EINVAL;
			break;
		}

		assert(*obj == nullptr);
		*obj = nullptr;

		std::unique_ptr<relay_connection_t> ptr =
			std::make_unique<relay_connection_t>();
		if(!ptr) {
			rv = -ENOMEM;
			break;
		}

		ptr->ObjectID = OBJID_RELAY_CONNECTION;
		ptr->Index = OBJ_INDEX_INVALID;
		ptr->Handle = nullptr;

		{
			std::lock_guard<std::mutex> lock(g_mtxConnections);
			//	get the lowest free index
			uint32_t index = 0;
			for(;; ++index) {
				if(g_Connections.find(index) == g_Connections.end()) {
					break;
				}
			}
			if(index >= OBJ_INDEX_MAX) {
				rv = -E2BIG;
				break;
			}

			ptr->Index = index;
		}

		RelayConnection* conn = RelayConnection::create(relayIP, relayPort);
		if(conn == nullptr) {
			rv = -ENOMEM;
			break;
		}
		ptr->Handle = reinterpret_cast<void*>(conn);

		*obj = ptr.release();
		{
			std::lock_guard<std::mutex> lock(g_mtxConnections);
			g_Connections[(*obj)->Index] = *obj;
		}

		rv = 0;
	} while(0);

	if(g_hostApp != nullptr)
		g_hostApp->trace(g_hostApp, "RelayConnection_Create: %d", rv);
	return rv;
}

int RelayConnection_Start(
	relay_connection_t* relay) {
	PROFILE();

	if(g_hostApp != nullptr)
		g_hostApp->trace(g_hostApp, "=> RelayConnection_Start");

	int rv = 0;
	do {
		if(relay == nullptr) {
			rv = -EINVAL;
			break;
		}

		if(relay->ObjectID == OBJID_RELAY_CONNECTION) {
			RelayConnection* conn =
				reinterpret_cast<RelayConnection*>(relay->Handle);
			if(conn == nullptr) {
				rv = -ENOEXEC;
				break;
			}
			rv = conn->start();
			break;
		}

		rv = -EINVAL;
	} while(0);

	if(g_hostApp != nullptr)
		g_hostApp->trace(g_hostApp, "RelayConnection_Start: %d", rv);
	return rv;
}

int RelayConnection_Stop(
	relay_connection_t* relay) {
	PROFILE();

	if(g_hostApp != nullptr)
		g_hostApp->trace(g_hostApp, "=> RelayConnection_Stop");

	int rv = 0;
	do {
		if(relay == nullptr) {
			rv = -EINVAL;
			break;
		}

		if(relay->ObjectID == OBJID_RELAY_CONNECTION) {
			RelayConnection* conn =
				reinterpret_cast<RelayConnection*>(relay->Handle);
			if(conn == nullptr) {
				rv = -ENOEXEC;
				break;
			}
			rv = conn->stop();
			break;
		}

		rv = -EINVAL;
	} while(0);

	if(g_hostApp != nullptr)
		g_hostApp->trace(g_hostApp, "RelayConnection_Stop: %d", rv);
	return rv;
}

int RelayConnection_Destroy(
	relay_connection_t* relay) {
	PROFILE();

	if(g_hostApp != nullptr)
		g_hostApp->trace(g_hostApp, "=> RelayConnection_Destroy");

	if(relay == nullptr) {
		if(g_hostApp != nullptr)
			g_hostApp->trace(g_hostApp, "relay is nullptr");
		return -ENOENT;
	}
	
	int rv = 0;
	do {
		if(relay->ObjectID == OBJID_RELAY_CONNECTION) {
			//	remove the object from the map
			{
				std::lock_guard<std::mutex> lock(g_mtxConnections);
				assert(g_Connections.find(relay->Index) != g_Connections.end());
				g_Connections.erase(relay->Index);
			}

			//	delete the connection
			RelayConnection* conn =
				reinterpret_cast<RelayConnection*>(relay->Handle);
			relay->Handle = nullptr;

			if(conn != nullptr) {
				conn->release();
			}
			rv = 0;
			break;
		}

		//	object not known
		rv = -EINVAL;
	} while(0);

	if(g_hostApp != nullptr)
		g_hostApp->trace(g_hostApp, "RelayConnection_Destroy: %d", rv);
	return rv;
}
