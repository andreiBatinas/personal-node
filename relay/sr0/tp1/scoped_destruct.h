#pragma once

#include <functional>

struct scoped_destruct {
private:
	std::function<void(void)> dtor_;
public:
	scoped_destruct(std::function<void(void)> dtor = nullptr);
	~scoped_destruct();
private:
	scoped_destruct(const scoped_destruct&) = delete;
	scoped_destruct(scoped_destruct&&) = delete;
	scoped_destruct& operator=(const scoped_destruct&) = delete;
	scoped_destruct& operator=(scoped_destruct&&) = delete;
public:
	void cancel();
	void reset(std::function<void(void)> dtor = nullptr);
};
