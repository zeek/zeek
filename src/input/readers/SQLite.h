// See the file "COPYING" in the main distribution directory for copyright.
//

#ifndef INPUT_READERS_POSTGRES_H
#define INPUT_READERS_POSTGRES_H

#include "config.h"

#ifdef USE_SQLITE

#include <iostream>
#include <vector>

#include "../ReaderBackend.h"
#include "../../threading/AsciiInputOutput.h"

#include "sqlite3.h"


namespace input { namespace reader {

class SQLite : public ReaderBackend {
public:
	SQLite(ReaderFrontend* frontend);
	~SQLite();
    
	static ReaderBackend* Instantiate(ReaderFrontend* frontend) { return new SQLite(frontend); }
    
protected:
	virtual bool DoInit(const ReaderInfo& info, int arg_num_fields, const threading::Field* const* fields); 

	virtual void DoClose();

	virtual bool DoUpdate();

	virtual bool DoHeartbeat(double network_time, double current_time)	{ return true; }	
private:
	bool checkError(int code);	

	unsigned int num_fields;

	const threading::Field* const * fields; // raw mapping		

	threading::Value* EntryToVal(sqlite3_stmt *st, const threading::Field *field, int pos);

	int mode;

	bool started;
	string query;

	sqlite3 *db;
	sqlite3_stmt *st;

	AsciiInputOutput* io;

};


}
}

#endif /* USE_SQLITE */

#endif /* INPUT_READERS_POSTGRES_H */

