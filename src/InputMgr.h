// See the file "COPYING" in the main distribution directory for copyright.

#ifndef INPUTMGR_H
#define INPUTMGR_H

#include "InputReader.h"
#include "BroString.h"

#include "Val.h"
#include "EventHandler.h"
#include "RemoteSerializer.h"
#include "LogMgr.h" // for the LogVal and LogType data types

class InputReader;

class InputMgr {
public:
    InputMgr();
    
    InputReader* CreateReader(EnumVal* reader, RecordVal* description);
	
protected:
	friend class InputReader;
	
	// Reports an error for the given reader.
	void Error(InputReader* reader, const char* msg);
	
private:
	// required functionality
	// InputValsToRecord to convert received inputvals back to bro records / tables / whatever
	Val* LogValToVal(const LogVal* val);

	void SendEvent(const string& name, const int num_vals, const LogVal* const *vals);

};

extern InputMgr* input_mgr;


#endif /* INPUTMGR_H */
