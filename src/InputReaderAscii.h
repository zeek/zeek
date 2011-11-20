// See the file "COPYING" in the main distribution directory for copyright.

#ifndef INPUTREADERASCII_H
#define INPUTREADERASCII_H

#include "InputReader.h"
#include <fstream>
#include <iostream>
#include <vector>

// Description for input field mapping
struct FieldMapping {
	string name;
	TypeTag type;
	TypeTag subtype;
	int position;

	FieldMapping(const string& arg_name, const TypeTag& arg_type, int arg_position); 
	FieldMapping(const string& arg_name, const TypeTag& arg_type, const TypeTag& arg_subtype, int arg_position); 
	FieldMapping(const FieldMapping& arg);
	FieldMapping() { position = -1; }

	FieldMapping subType();
	bool IsEmpty() { return position == -1; }
};


class InputReaderAscii : public InputReader {
public:
    InputReaderAscii();
    ~InputReaderAscii();
    
    static InputReader* Instantiate() { return new InputReaderAscii; }
    
protected:
	
	virtual bool DoInit(string path);

	virtual bool DoAddFilter( int id, int arg_num_fields, const LogField* const* fields );

	virtual bool DoRemoveFilter ( int id );	

	virtual void DoFinish();

	virtual bool DoUpdate();
    
private:

	struct Filter {
		unsigned int num_fields;

		const LogField* const * fields; // raw mapping		

		// map columns in the file to columns to send back to the manager
		vector<FieldMapping> columnMap;		

	};

	bool HasFilter(int id);

	bool ReadHeader();
	LogVal* EntryToVal(string s, FieldMapping type);

	bool GetLine(string& str);
	
	ifstream* file;
	string fname;

	map<int, Filter> filters;

	// Options set from the script-level.
	string separator;

	string set_separator;

	string empty_field;

	string unset_field;

};


#endif /* INPUTREADERASCII_H */
