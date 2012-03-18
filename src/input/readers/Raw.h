// See the file "COPYING" in the main distribution directory for copyright.

#ifndef INPUT_READERS_RAW_H
#define INPUT_READERS_RAW_H

#include <iostream>
#include <vector>

#include "../ReaderBackend.h"

namespace input { namespace reader {

class Raw : public ReaderBackend {
public:
    Raw(ReaderFrontend* frontend);
    ~Raw();
    
    static ReaderBackend* Instantiate(ReaderFrontend* frontend) { return new Raw(frontend); }
    
protected:
	
	virtual bool DoInit(string path, int mode, int arg_num_fields, const threading::Field* const* fields);

	virtual void DoFinish();

	virtual bool DoUpdate();

private:

	virtual bool DoHeartbeat(double network_time, double current_time);

	bool GetLine(string& str);
	
	istream* in;
	ifstream* file;

	FILE* pfile;
	
	string fname;

	// Options set from the script-level.
	string separator;

	// keep a copy of the headerline to determine field locations when filters change
	string headerline;

	int mode;

	time_t mtime;
	
	unsigned int num_fields;

	const threading::Field* const * fields; // raw mapping		

};


}
}

#endif /* INPUT_READERS_RAW_H */
