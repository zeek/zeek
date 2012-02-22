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
	
	virtual bool DoInit(string path, int mode);

	virtual bool DoAddFilter( int id, int arg_num_fields, const threading::Field* const* fields );

	virtual bool DoRemoveFilter ( int id );	

	virtual void DoFinish();

	virtual bool DoUpdate();

	virtual bool DoStartReading();
    
private:

	virtual bool DoHeartbeat(double network_time, double current_time);

	struct Filter {
		unsigned int num_fields;

		const threading::Field* const * fields; // raw mapping		
	};

	bool HasFilter(int id);

	bool GetLine(string& str);
	
	ifstream* file;
	string fname;

	map<int, Filter> filters;

	// Options set from the script-level.
	string separator;

	// keep a copy of the headerline to determine field locations when filters change
	string headerline;

	int mode;

	bool started;
	time_t mtime;

};


}
}

#endif /* INPUT_READERS_RAW_H */
