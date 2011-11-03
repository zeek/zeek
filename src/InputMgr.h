// See the file "COPYING" in the main distribution directory for copyright.

#ifndef INPUTMGR_H
#define INPUTMGR_H

#include "InputReader.h"
#include "BroString.h"

#include "Val.h"
#include "EventHandler.h"
#include "RemoteSerializer.h"
#include "LogMgr.h" // for the LogVal and LogType data types

#include <vector>

class InputReader;


class InputMgr {
public:
	InputMgr();
    
    	InputReader* CreateReader(EnumVal* id, RecordVal* description);
	bool ForceUpdate(const EnumVal* id);
	bool RemoveReader(const EnumVal* id);	
	bool RegisterEvent(const EnumVal* id, string eventName);
	bool UnregisterEvent(const EnumVal* id, string eventName);

	
protected:
	friend class InputReader;
	
	// Reports an error for the given reader.
	void Error(InputReader* reader, const char* msg);

	void Put(const InputReader* reader, const LogVal* const *vals);
	void Clear(const InputReader* reader);
	bool Delete(const InputReader* reader, const LogVal* const *vals);

	void SendEntry(const InputReader* reader, const LogVal* const *vals);
	void EndCurrentSend(const InputReader* reader);
	
private:
	struct ReaderInfo;

	bool IsCompatibleType(BroType* t);

	bool UnrollRecordType(vector<LogField*> *fields, const RecordType *rec, const string& nameprepend);
	void SendEvent(const string& name, EnumVal* event, Val* left, Val* right);	

	HashKey* HashLogVals(const int num_elements, const LogVal* const *vals);

	Val* LogValToVal(const LogVal* val, TypeTag request_type = TYPE_ANY);
	Val* LogValToIndexVal(int num_fields, const RecordType* type, const LogVal* const *vals);
	Val* LogValToRecordVal(const LogVal* const *vals, RecordType *request_type, int* position);	

	void SendEvent(const string& name, const int num_vals, const LogVal* const *vals);
	ReaderInfo* FindReader(const InputReader* reader);
	ReaderInfo* FindReader(const EnumVal* id);

	vector<ReaderInfo*> readers;

	string Hash(const string &input);	

};

extern InputMgr* input_mgr;


#endif /* INPUTMGR_H */
