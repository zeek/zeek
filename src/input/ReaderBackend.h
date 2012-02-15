// See the file "COPYING" in the main distribution directory for copyright.

#ifndef INPUT_READERBACKEND_H
#define INPUT_READERBACKEND_H

#include "BroString.h"
#include "../threading/SerializationTypes.h"
#include "threading/MsgThread.h"

namespace input {

class ReaderFrontend;

class ReaderBackend : public threading::MsgThread {
public:
	ReaderBackend(ReaderFrontend* frontend);
    	
	virtual ~ReaderBackend();
	
	bool Init(string arg_source);

	bool AddFilter( int id, int arg_num_fields, const threading::Field* const* fields );

	bool RemoveFilter ( int id );
    
	void Finish();

	bool Update();

	/**
	 * Disables the frontend that has instantiated this backend. Once
	 * disabled,the frontend will not send any further message over.
	 */
	void DisableFrontend();	
	
protected:
    // Methods that have to be overwritten by the individual readers
	virtual bool DoInit(string arg_sources) = 0;

	virtual bool DoAddFilter( int id, int arg_num_fields, const threading::Field* const* fields ) = 0;

	virtual bool DoRemoveFilter( int id ) = 0;

	virtual void DoFinish() = 0;

	// update file contents to logmgr
	virtual bool DoUpdate() = 0;
	
	// The following methods return the information as passed to Init().
	const string Source() const	{ return source; }

	void SendEvent(const string& name, const int num_vals, threading::Value* *vals);

	// Content-sendinf-functions (simple mode). Including table-specific stuff that simply is not used if we have no table
	void Put(int id, threading::Value* *val);
	void Delete(int id, threading::Value* *val);
	void Clear(int id);

	// Table-functions (tracking mode): Only changed lines are propagated.
	void SendEntry(int id, threading::Value*  *vals);
	void EndCurrentSend(int id);
	

private:
	// Frontend that instantiated us. This object must not be access from
	// this class, it's running in a different thread!
	ReaderFrontend* frontend;	

	string source;
    
    	// When an error occurs, this method is called to set a flag marking the 
    	// writer as disabled.
    
    	bool disabled;
    	bool Disabled() { return disabled; }

	// For implementing Fmt().
	char* buf;
	unsigned int buf_len;    
};

}

#endif /* INPUT_READERBACKEND_H */
