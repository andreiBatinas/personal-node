#include "event.h"
#include <cassert>
#include <utility>

namespace os {
event_t::event_t() {
}

event_t::~event_t() {
	close();
}

event_t::operator bool() const {
	return is_open();
}

bool event_t::operator !() const {
	return !is_open();
}

event_t::operator HANDLE() {
	return h_;
}

HANDLE* event_t::operator&() {
	return &h_;
}

bool event_t::is_open() const {
	return h_ != nullptr;
}

bool event_t::create() {
	assert(h_ == nullptr);
	if(is_open())
		return false;
	h_ = CreateEventA(nullptr, FALSE, FALSE, nullptr);
	return h_ != nullptr;
}

void event_t::close() {
	HANDLE h = std::move(h_);
	if(h != nullptr)
		CloseHandle(h);
}

bool event_t::set() {
	if(!is_open())
		return false;
	return !!::SetEvent(h_);
}

} // namespace os
