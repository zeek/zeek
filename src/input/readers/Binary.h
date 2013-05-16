// See the file "COPYING" in the main distribution directory for copyright.

#ifndef INPUT_READERS_BINARY_H
#define INPUT_READERS_BINARY_H

#include <fstream>

#include "../ReaderBackend.h"

namespace input { namespace reader {

/**
 * Binary mode file reader.
 */
class Binary : public ReaderBackend {
public:
	Binary(ReaderFrontend* frontend);

	~Binary();

	static ReaderBackend* Instantiate(ReaderFrontend* frontend)
		{ return new Binary(frontend); }

protected:
	virtual bool DoInit(const ReaderInfo& info, int arg_num_fields,
	                    const threading::Field* const* fields);
	virtual void DoClose();
	virtual bool DoUpdate();
	virtual bool DoHeartbeat(double network_time, double current_time);

private:
	bool OpenInput();
	bool CloseInput();
	streamsize GetChunk(char** chunk);
	int UpdateModificationTime();

	string fname;
	ifstream* in;
	time_t mtime;
	bool firstrun;

	// options set from the script-level.
	static streamsize chunk_size;
};

}
}

#endif /* INPUT_READERS_BINARY_H */
