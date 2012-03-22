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
	// internal type for sets and vectors
	TypeTag subtype;
	int position;
	// for ports: pos of the second field
	int secondary_position;
	bool present;

	FieldMapping(const string& arg_name, const TypeTag& arg_type, int arg_position); 
	FieldMapping(const string& arg_name, const TypeTag& arg_type, const TypeTag& arg_subtype, int arg_position); 
	FieldMapping(const FieldMapping& arg);
	FieldMapping() { position = -1; secondary_position = -1; }

	FieldMapping subType();
	//bool IsEmpty() { return position == -1; }
};


class Ascii : public ReaderBackend {
public:
    Ascii(ReaderFrontend* frontend);
    ~Ascii();
    
    static ReaderBackend* Instantiate(ReaderFrontend* frontend) { return new Ascii(frontend); }
    
protected:
	
	virtual bool DoInit(string path, int mode, int arg_num_fields, const threading::Field* const* fields);

	virtual void DoFinish();

	virtual bool DoUpdate();

private:

	virtual bool DoHeartbeat(double network_time, double current_time);

	unsigned int num_fields;

	const threading::Field* const * fields; // raw mapping		

	// map columns in the file to columns to send back to the manager
	vector<FieldMapping> columnMap;		

	bool ReadHeader(bool useCached);
	threading::Value* EntryToVal(string s, FieldMapping type);

	bool GetLine(string& str);
	
	ifstream* file;
	string fname;

	// Options set from the script-level.
	string separator;

	string set_separator;

	string empty_field;

	string unset_field;
	
	// keep a copy of the headerline to determine field locations when filters change
	string headerline;

	int mode;

	time_t mtime;

};


}
}

#endif /* INPUT_READERS_ASCII_H */
