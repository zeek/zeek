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
	int position;

	FieldMapping(const string& arg_name, const TypeTag& arg_type, int arg_position); 
	FieldMapping(const FieldMapping& arg);
	FieldMapping() { position = -1; }
	bool IsEmpty() { return position == -1; }
};


class InputReaderAscii : public InputReader {
public:
    InputReaderAscii();
    ~InputReaderAscii();
    
    static InputReader* Instantiate() { return new InputReaderAscii; }
    
protected:
	
	virtual bool DoInit(string path, int num_fields,
						const LogField* const * fields);
	virtual void DoFinish();

	virtual bool DoUpdate();
    
private:
	
	ifstream* file;
	string fname;

	unsigned int num_fields;

	// map columns in the file to columns to send back to the manager
	vector<FieldMapping> columnMap;
	
};


#endif /* INPUTREADERASCII_H */
