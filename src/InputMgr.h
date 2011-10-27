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

	void Put(const InputReader* reader, const LogVal* const *vals);
	
private:
	struct ReaderInfo;

	Val* LogValToVal(const LogVal* val);

	void SendEvent(const string& name, const int num_vals, const LogVal* const *vals);
	ReaderInfo* FindReader(const InputReader* reader);

	vector<ReaderInfo*> readers;
};

extern InputMgr* input_mgr;


#endif /* INPUTMGR_H */
