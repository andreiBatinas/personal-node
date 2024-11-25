#pragma once

class RelayConnection {
private:
	RelayConnection(const char* relayIP,
		int relayPort);
	~RelayConnection();

public:
	int start();
	int stop();

	static RelayConnection* create(const char* relayIP, int relayPort);
	void release();

private:
	RelayConnection(const RelayConnection&) = delete;
	RelayConnection(RelayConnection&&) = delete;

	RelayConnection& operator=(const RelayConnection&) = delete;
	RelayConnection&& operator=(RelayConnection&&) = delete;
};
