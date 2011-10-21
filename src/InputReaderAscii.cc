
#include "InputReaderAscii.h"
#include "DebugLogger.h"

#include <sstream>

InputReaderAscii::InputReaderAscii()
{
	//DBG_LOG(DBG_LOGGING, "input reader initialized");
	file = 0;
}

InputReaderAscii::~InputReaderAscii()
{
}

void InputReaderAscii::DoFinish()
{
}

bool InputReaderAscii::DoInit(string path, int num_fields,
							  const LogField* const * fields)
{
	fname = path;
	
	file = new ifstream(path.c_str());
	if ( !file->is_open() ) {
		return false;
	}

	// try to read the header line...
	string line;
	if ( !getline(*file, line) ) 
		return false;
	 
	// split on tabs...
	istringstream ss(line);
	while ( ss ) {
		string s;
		if ( !getline(ss, s, '\t'))
			break;
		
		
	} 
	
	
	return false;
}