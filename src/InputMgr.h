// See the file "COPYING" in the main distribution directory for copyright.

#ifndef INPUTMGR_H
#define INPUTMGR_H

#include "InputReader.h"
#include "BroString.h"

#include "Val.h"
#include "EventHandler.h"
#include "RemoteSerializer.h"

class InputReader;

class InputMgr {
public:
    InputMgr();
    
    InputReader* CreateReader(EnumVal* reader, string source, string eventName, RecordVal* eventDescription);
	
protected:
	friend class InputReader;
	
	// Reports an error for the given reader.
	void Error(InputReader* reader, const char* msg);

};

extern InputMgr* input_mgr;


#endif /* INPUTMGR_H */
