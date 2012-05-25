// See the file "COPYING" in the main distribution directory for copyright.

#ifndef INPUT_READERS_ASCII_H
#define INPUT_READERS_ASCII_H

#include <iostream>
#include <vector>

#include "../ReaderBackend.h"

namespace input { namespace reader {

// Description for input field mapping
struct FieldMapping {
	string name;
	TypeTag type;
	TypeTag subtype; // internal type for sets and vectors
	int position;
	int secondary_position; // for ports: pos of the second field
	bool present;

	FieldMapping(const string& arg_name, const TypeTag& arg_type, int arg_position);
	FieldMapping(const string& arg_name, const TypeTag& arg_type, const TypeTag& arg_subtype, int arg_position);
	FieldMapping(const FieldMapping& arg);
	FieldMapping() { position = -1; secondary_position = -1; }

	FieldMapping subType();
};

class Ascii : public ReaderBackend {
public:
	Ascii(ReaderFrontend* frontend);
	~Ascii();

	static ReaderBackend* Instantiate(ReaderFrontend* frontend) { return new Ascii(frontend); }

protected:
	virtual bool DoInit(string path, int mode, int arg_num_fields, const threading::Field* const* fields);
	virtual void DoClose();
	virtual bool DoUpdate();

private:
	virtual bool DoHeartbeat(double network_time, double current_time);

	bool ReadHeader(bool useCached);
	bool GetLine(string& str);
	threading::Value* EntryToVal(string s, FieldMapping type);

	unsigned int num_fields;
	const threading::Field* const *fields; // raw mapping

	ifstream* file;
	string fname;
	int mode;
	time_t mtime;

	// map columns in the file to columns to send back to the manager
	vector<FieldMapping> columnMap;

	// keep a copy of the headerline to determine field locations when stream descriptions change
	string headerline;

	// Options set from the script-level.
	string separator;
	string set_separator;
	string empty_field;
	string unset_field;
};


}
}

#endif /* INPUT_READERS_ASCII_H */
