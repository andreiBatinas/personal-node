#pragma once

#include "logger.h"
#include <cinttypes>

//	general purpose init/uninit
static constexpr uint32_t RELAY_INIT_FLAG_NOT_INIT = 0xFFFFFFFF;
static constexpr uint32_t RELAY_INIT_FLAG_NONE     = 0x00000000;
static constexpr uint32_t RELAY_INIT_FLAG_SOCKETS  = 0x00000001;
static constexpr uint32_t RELAY_INIT_FLAG_SSL      = 0x00000002;
int Relay_Init(
	uint32_t flags);
int Relay_Shutdown(
	void);

struct relay_host_application_t {
	int  (* addRef)(struct relay_host_application_t* host);
	int  (* release)(struct relay_host_application_t* host);
	void (* log)(struct relay_host_application_t* host,
		logger::LEVEL level, const char* fmt, ...);
	void (__cdecl* error)(struct relay_host_application_t* host,
		const char* fmt, ...);
	void (__cdecl* warning)(struct relay_host_application_t* host,
		const char* fmt, ...);
	void (__cdecl* info)(struct relay_host_application_t* host,
		const char* fmt, ...);
	void (__cdecl* trace)(struct relay_host_application_t* host,
		const char* fmt, ...);
};
int Relay_SetHostApp(
	struct relay_host_application_t* host);

//	relay connection API
struct relay_connection_t {
	uint32_t ObjectID;
	uint32_t Index;
	void* Handle;
};

int RelayConnection_Create(
	struct relay_connection_t** obj,
	const char* relayIP,
	int relayPort);
int RelayConnection_Start(
	struct relay_connection_t* obj);
int RelayConnection_Stop(
	struct relay_connection_t* obj);
int RelayConnection_Destroy(
	struct relay_connection_t* obj);
