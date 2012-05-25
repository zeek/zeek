// See the file "COPYING" in the main distribution directory for copyright.

#ifndef INPUT_READERS_RAW_H
#define INPUT_READERS_RAW_H

#include <iostream>
#include <vector>

#include "../ReaderBackend.h"

namespace input { namespace reader {

/**
 * A reader that returns a file (or the output of a command) as a single
 * blob.
 */
class Raw : public ReaderBackend {
public:
	Raw(ReaderFrontend* frontend);
	~Raw();

	static ReaderBackend* Instantiate(ReaderFrontend* frontend) { return new Raw(frontend); }

protected:
	virtual bool DoInit(string path, int mode, int arg_num_fields, const threading::Field* const* fields);
	virtual void DoClose();
	virtual bool DoUpdate();

private:
	virtual bool DoHeartbeat(double network_time, double current_time);

	bool Open();
	bool Close();
	bool GetLine(string& str);

	unsigned int num_fields;
	const threading::Field* const * fields; // raw mapping

	istream* in;
	FILE* file;
	string fname;
	int mode;
	bool execute;
	bool firstrun;
	time_t mtime;

	// Options set from the script-level.
	string separator;
};

}
}

#endif /* INPUT_READERS_RAW_H */
