#pragma once

#include <windows.h>

namespace os {

class event_t {
private:
	HANDLE h_ = nullptr;
public:
	event_t();
	~event_t();
private:
	event_t(const event_t&) = delete;
	event_t(event_t&&) = delete;
	event_t& operator=(const event_t&) = delete;
	event_t&& operator=(event_t&&) = delete;
public:
	operator bool() const;
	bool operator !() const;
	operator HANDLE();
	HANDLE* operator&();
	bool is_open() const;
	bool create();
	void close();
	bool set();
};

} // namespace os
