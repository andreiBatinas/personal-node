#include "relay_api.h"
#include "relay_starter.h"
#include <memory>

#if 0

//
//	C-like API interface
//
static constexpr int OBJID_NONE = 0x0;
static constexpr int OBJID_RELAY_CONNECTION = 0x1;

int RelayConnection_Create(
	relay_connection_t* relayer,
	const char* relayIP,
	int relayPort) {
	if(relayer == nullptr) {
		return -EINVAL;
	}

	std::unique_ptr<RelayConnectionStarter> starter =
		std::make_unique<RelayConnectionStarter>(relayIP, relayPort);
	if(!starter) {
		return -ENOMEM;
	}

	relayer->ObjectID = OBJID_RELAY_CONNECTION;
	relayer->Handle = reinterpret_cast<void*>(starter.release());
	return 0;
}

int RelayConnection_Start(
	relay_connection_t* relayer) {
	if(relayer == nullptr) {
		return -EINVAL;
	}
	if(relayer->ObjectID != OBJID_RELAY_CONNECTION) {
		return -EINVAL;
	}
	RelayConnectionStarter* starter =
		reinterpret_cast<RelayConnectionStarter*>(relayer->Handle);
	if(starter == nullptr) {
		return -ENOEXEC;
	}
	return starter->start();
}

int RelayConnection_Stop(
	relay_connection_t* relayer) {
	if(relayer == nullptr)
		return -ENOENT;
	if(relayer->ObjectID != OBJID_RELAY_CONNECTION)
		return -EINVAL;
	RelayConnectionStarter* starter =
		reinterpret_cast<RelayConnectionStarter*>(relayer->Handle);
	if(starter == nullptr) {
		return -ENOEXEC;
	}
	return starter->stop();
}

int RelayConnection_Destroy(
	relay_connection_t* relayer) {
	if(relayer == nullptr)
		return -ENOENT;
	if(relayer->ObjectID != OBJID_RELAY_CONNECTION)
		return -EINVAL;
	RelayConnectionStarter* starter =
		reinterpret_cast<RelayConnectionStarter*>(relayer->Handle);
	delete starter;
	relayer->Handle = nullptr;
	return 0;
}

#endif
