#include "relay_connection.h"
#include "logger.h"

RelayConnection::RelayConnection(const char* relayIP,
	int relayPort) {
}

RelayConnection::~RelayConnection() {
}

int RelayConnection::start() {
	return 0;
}

int RelayConnection::stop() {
	return 0;
}

RelayConnection* RelayConnection::create(const char* relayIP,
	int relayPort) {
	return new RelayConnection(relayIP, relayPort);
}

void RelayConnection::release() {
	delete this;
}
