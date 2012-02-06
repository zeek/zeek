// See the file "COPYING" in the main distribution directory for copyright.

#ifndef INPUT_READERFRONTEND_H
#define INPUT_READERFRONTEND_H

#include "Manager.h"

#include "threading/MsgThread.h"

namespace logging {

class ReaderBackend;

class ReaderFrontend {

	ReaderFrontend(bro_int_t type);

	virtual ~ReaderFrontend();


protected:
	friend class Manager;
};

}

#endif /* INPUT_READERFRONTEND_H */

