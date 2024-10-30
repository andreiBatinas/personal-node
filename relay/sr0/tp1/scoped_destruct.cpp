#include "scoped_destruct.h"

scoped_destruct::scoped_destruct(std::function<void(void)> dtor) 
	: dtor_(dtor) {
}

scoped_destruct::~scoped_destruct() {
	if (dtor_ != nullptr) {
		dtor_();
	}
}

void scoped_destruct::cancel() {
	reset(nullptr);
}

void scoped_destruct::reset(std::function<void(void)> dtor) {
	dtor_ = dtor;
}
