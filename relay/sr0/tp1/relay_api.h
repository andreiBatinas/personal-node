#pragma once

struct relay_connection_t {
	int ObjectID;
	void* Handle;
};

int RelayConnection_Create(
	struct relay_connection_t* relayer,
	const char* relayIP,
	int relayPort);
int RelayConnection_Start(
	struct relay_connection_t* relayer);
int RelayConnection_Stop(
	struct relay_connection_t* relayer);
int RelayConnection_Destroy(
	struct relay_connection_t* relayer);
