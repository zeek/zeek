// See the file "COPYING" in the main distribution directory for copyright.

#include "InputReaderAscii.h"
#include "DebugLogger.h"

#include <sstream>

FieldMapping::FieldMapping(const string& arg_name, const TypeTag& arg_type, int arg_position) 
	: name(arg_name), type(arg_type)
{
	position = arg_position;
}

FieldMapping::FieldMapping(const string& arg_name, const TypeTag& arg_type, const TypeTag& arg_set_type, int arg_position) 
	: name(arg_name), type(arg_type), set_type(arg_set_type)
{
	position = arg_position;
}

FieldMapping::FieldMapping(const FieldMapping& arg) 
	: name(arg.name), type(arg.type), set_type(arg.set_type)
{
	position = arg.position;
}

FieldMapping FieldMapping::setType() {
	return FieldMapping(name, set_type, position);
}

InputReaderAscii::InputReaderAscii()
{
	//DBG_LOG(DBG_LOGGING, "input reader initialized");
	file = 0;

	//keyMap = new map<string, string>();
}

InputReaderAscii::~InputReaderAscii()
{
	DoFinish();
}

void InputReaderAscii::DoFinish()
{
	columnMap.empty();
	if ( file != 0 ) {
		file->close();
		delete(file);
		file = 0;
	}
}

bool InputReaderAscii::DoInit(string path, int num_fields, int idx_fields, const LogField* const * fields)
{
	fname = path;
	
	file = new ifstream(path.c_str());
	if ( !file->is_open() ) {
		Error(Fmt("cannot open %s", fname.c_str()));
		return false;
	}


	this->num_fields = num_fields;
	this->idx_fields = idx_fields;
	this->fields = fields;

	return true;
}


bool InputReaderAscii::ReadHeader() {	 
	// try to read the header line...
	string line;
	if ( !GetLine(line) ) {
		Error("could not read first line");
		return false;
	}

	// split on tabs...
	istringstream splitstream(line);
	unsigned int currTab = 0;
	int wantFields = 0;
	while ( splitstream ) {
		string s;
		if ( !getline(splitstream, s, '\t'))
			break;
		
		// current found heading in s... compare if we want it
		for ( unsigned int i = 0; i < num_fields; i++ ) {
			const LogField* field = fields[i];
			if ( field->name == s ) {
				// cool, found field. note position
				FieldMapping f(field->name, field->type, field->set_type, i);
				columnMap.push_back(f);
				wantFields++;
				break; // done with searching
			}
		}

		// look if we did push something...
		if ( columnMap.size() == currTab ) {
			// no, we didn't. note that...
			FieldMapping empty;
			columnMap.push_back(empty);
		}

		// done 
		currTab++;
	} 

	if ( wantFields != (int) num_fields ) {
		// we did not find all fields?
		// :(
		Error("One of the requested fields could not be found in the input data file");
		return false;
	}
	
	
	// well, that seems to have worked...
	return true;
}

bool InputReaderAscii::GetLine(string& str) {
	while ( getline(*file, str) ) {
		if ( str[0] != '#' ) {
			return true;
		}

		if ( str.compare(0,8, "#fields\t") == 0 ) {
			str = str.substr(8);
			return true;
		}
	}

	return false;
}


LogVal* InputReaderAscii::EntryToVal(string s, FieldMapping field) {

	LogVal* val = new LogVal(field.type, true);
	//bzero(val, sizeof(LogVal));

	switch ( field.type ) {
	case TYPE_ENUM:
	case TYPE_STRING:
		val->val.string_val = new string(s);
		break;

	case TYPE_BOOL:
		if ( s == "T" ) {
			val->val.int_val = 1;
		} else if ( s == "F" ) {
			val->val.int_val = 0;
		} else {
			Error(Fmt("Invalid value for boolean: %s", s.c_str()));
			return false;
		}
		break;

	case TYPE_INT:
		val->val.int_val = atoi(s.c_str());
		break;

	case TYPE_DOUBLE:
	case TYPE_TIME:
	case TYPE_INTERVAL:
		val->val.double_val = atof(s.c_str());
		break;

	case TYPE_COUNT:
	case TYPE_COUNTER:
	case TYPE_PORT:
		val->val.uint_val = atoi(s.c_str());
		break;

	case TYPE_SUBNET: {
		int pos = s.find("/");
		string width = s.substr(pos+1);
		val->val.subnet_val.width = atoi(width.c_str());
		string addr = s.substr(0, pos);
		s = addr;
		// NOTE: dottet_to_addr BREAKS THREAD SAFETY! it uses reporter.
		// Solve this some other time....
		val->val.subnet_val.net = dotted_to_addr(s.c_str());
		break;

		}
	case TYPE_ADDR: {
		// NOTE: dottet_to_addr BREAKS THREAD SAFETY! it uses reporter.
		// Solve this some other time....
		addr_type t =  dotted_to_addr(s.c_str());
#ifdef BROv6
		copy_addr(t, val->val.addr_val);
#else
		copy_addr(&t, val->val.addr_val);
#endif
		break;
		}

	case TYPE_TABLE: {
		// construct a table from entry...
		// for the moment assume, that entries are split by ",".

		if ( s == "-" ) {
			// empty 
			val->val.set_val.size = 0;
			break;
		}

		// how many entries do we have...
		unsigned int length = 1;
		for ( unsigned int i = 0; i < s.size(); i++ )
			if ( s[i] == ',') length++;

		unsigned int pos = 0;
		LogVal** lvals = new LogVal* [length];
		val->val.set_val.vals = lvals;
		val->val.set_val.size = length;

		istringstream splitstream(s);
		while ( splitstream ) {
			string element;

			if ( pos >= length ) {
				Error(Fmt("Internal error while parsing set. pos %d > length %d", pos, length));
				break;
			}

			if ( !getline(splitstream, element, ',') )
				break;
			

			LogVal* newval = EntryToVal(element, field.setType());
			if ( newval == 0 ) {
				Error("Error while reading set");
				return 0;
			}
			lvals[pos] = newval;

			pos++;
	
		}

		if ( pos != length ) {
			Error("Internal error while parsing set: did not find all elements");
			return 0;
		}

		break;
		}


	default:
		Error(Fmt("unsupported field format %d for %s", field.type,
		field.name.c_str()));
		return 0;
	}	

	return val;

}

// read the entire file and send appropriate thingies back to InputMgr
bool InputReaderAscii::DoUpdate() {
	 
	// dirty, fix me. (well, apparently after trying seeking, etc - this is not that bad)
	if ( file && file->is_open() ) {
		file->close();
	}
	file = new ifstream(fname.c_str());
	if ( !file->is_open() ) {
		Error(Fmt("cannot open %s", fname.c_str()));
		return false;
	}
	// 
	
	// file->seekg(0, ios::beg); // do not forget clear.


	if ( ReadHeader() == false ) {
		return false;
	}

	// TODO: all the stuff we need for a second reading.
	// *cough*
	//
	//
	

	// new keymap
	//map<string, string> *newKeyMap = new map<string, string>();

	string line;
	while ( GetLine(line ) ) {
		// split on tabs
		
		istringstream splitstream(line);
	
		LogVal** fields = new LogVal*[num_fields];
		//string string_fields[num_fields];

		unsigned int currTab = 0;
		unsigned int currField = 0;
		while ( splitstream ) {

			string s;
			if ( !getline(splitstream, s, '\t') )
				break;

			
			if ( currTab >= columnMap.size() ) {
				Error("Tabs in heading do not match tabs in data?");
				//disabled = true;
				return false;
			}

			FieldMapping currMapping = columnMap[currTab];
			currTab++;

			if ( currMapping.IsEmpty() ) {
				// well, that was easy
				continue;
			}

			if ( currField >= num_fields ) {
				Error("internal error - fieldnum greater as possible");
				return false;
			}

			LogVal* val = EntryToVal(s, currMapping);
			if ( val == 0 ) {
				return false;
			}
			fields[currMapping.position] = val;
			//string_fields[currMapping.position] = s;

			currField++;
		}

		if ( currField != num_fields ) {
			Error("curr_field != num_fields in DoUpdate. Columns in file do not match column definition.");
			return false;
		}


		SendEntry(fields);

		/* 
		string indexstring = "";
		string valstring = "";
		for ( unsigned int i = 0; i < idx_fields; i++ ) {
			indexstring.append(string_fields[i]);
		}

		for ( unsigned int i = idx_fields; i < num_fields; i++ ) {
			valstring.append(string_fields[i]);
		}

		string valhash = Hash(valstring);
		string indexhash = Hash(indexstring);

		if ( keyMap->find(indexhash) == keyMap->end() ) {
			// new key
			Put(fields);
		} else if ( (*keyMap)[indexhash] != valhash ) {
			// changed key
			Put(fields);
			keyMap->erase(indexhash);
		} else {
			// field not changed
			keyMap->erase(indexhash);
		}


		(*newKeyMap)[indexhash] = valhash;
		 */
		
		for ( unsigned int i = 0; i < num_fields; i++ ) {
			delete fields[i];
		}
		delete [] fields;

	}

	//file->clear(); // remove end of file evil bits
	//file->seekg(0, ios::beg); // and seek to start.

	EndCurrentSend();
	return true;
}
