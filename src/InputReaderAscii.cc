// See the file "COPYING" in the main distribution directory for copyright.

#include "InputReaderAscii.h"
#include "DebugLogger.h"
#include "NetVar.h"

#include <sstream>

FieldMapping::FieldMapping(const string& arg_name, const TypeTag& arg_type, int arg_position) 
	: name(arg_name), type(arg_type)
{
	position = arg_position;
}

FieldMapping::FieldMapping(const string& arg_name, const TypeTag& arg_type, const TypeTag& arg_subtype, int arg_position) 
	: name(arg_name), type(arg_type), subtype(arg_subtype)
{
	position = arg_position;
}

FieldMapping::FieldMapping(const FieldMapping& arg) 
	: name(arg.name), type(arg.type), subtype(arg.subtype)
{
	position = arg.position;
}

FieldMapping FieldMapping::subType() {
	return FieldMapping(name, subtype, position);
}


InputReaderAscii::InputReaderAscii()
{
	file = 0;

	//keyMap = new map<string, string>();
	
	separator.assign( (const char*) BifConst::InputAscii::separator->Bytes(), BifConst::InputAscii::separator->Len());
	if ( separator.size() != 1 ) {
		Error("separator length has to be 1. Separator will be truncated.");
	}

	set_separator.assign( (const char*) BifConst::InputAscii::set_separator->Bytes(), BifConst::InputAscii::set_separator->Len());
	if ( set_separator.size() != 1 ) {
		Error("set_separator length has to be 1. Separator will be truncated.");
	}

	empty_field.assign( (const char*) BifConst::InputAscii::empty_field->Bytes(), BifConst::InputAscii::empty_field->Len());
	
	unset_field.assign( (const char*) BifConst::InputAscii::unset_field->Bytes(), BifConst::InputAscii::unset_field->Len());
	
}

InputReaderAscii::~InputReaderAscii()
{
	DoFinish();

}

void InputReaderAscii::DoFinish()
{
	filters.empty();
	if ( file != 0 ) {
		file->close();
		delete(file);
		file = 0;
	}
}

bool InputReaderAscii::DoInit(string path)
{
	fname = path;
	
	file = new ifstream(path.c_str());
	if ( !file->is_open() ) {
		Error(Fmt("cannot open %s", fname.c_str()));
		return false;
	}

	return true;
}

bool InputReaderAscii::DoAddFilter( int id, int arg_num_fields, const LogField* const* fields ) {
	if ( HasFilter(id) ) {
		return false; // no, we don't want to add this a second time
	}

	Filter f;
	f.num_fields = arg_num_fields;
	f.fields = fields;

	filters[id] = f;

	return true;
}

bool InputReaderAscii::DoRemoveFilter ( int id ) {
	if (!HasFilter(id) ) {
		return false;
	}

	assert ( filters.erase(id) == 1 );

	return true;
}	


bool InputReaderAscii::HasFilter(int id) {
	map<int, Filter>::iterator it = filters.find(id);	
	if ( it == filters.end() ) {
		return false;
	}
	return true;
}


bool InputReaderAscii::ReadHeader() {	 
	// try to read the header line...
	string line;
	if ( !GetLine(line) ) {
		Error("could not read first line");
		return false;
	}

	for ( map<int, Filter>::iterator it = filters.begin(); it != filters.end(); it++ ) {
		// split on tabs...
		istringstream splitstream(line);
		unsigned int currTab = 0;
		int wantFields = 0;
		while ( splitstream ) {
			string s;
			if ( !getline(splitstream, s, separator[0]))
				break;
			
			// current found heading in s... compare if we want it
			for ( unsigned int i = 0; i < (*it).second.num_fields; i++ ) {
				const LogField* field = (*it).second.fields[i];
				if ( field->name == s ) {
					// cool, found field. note position
					FieldMapping f(field->name, field->type, field->subtype, i);
					(*it).second.columnMap.push_back(f);
					wantFields++;
					break; // done with searching
				}
			}

			// look if we did push something...
			if ( (*it).second.columnMap.size() == currTab ) {
				// no, we didn't. note that...
				FieldMapping empty;
				(*it).second.columnMap.push_back(empty);
			}

			// done 
			currTab++;
		} 

		if ( wantFields != (int) (*it).second.num_fields ) {
			// we did not find all fields?
			// :(
			Error(Fmt("One of the requested fields could not be found in the input data file. Found %d fields, wanted %d. Filternum: %d", wantFields, (*it).second.num_fields, (*it).first));
			return false;
		}
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

	if ( s.compare(unset_field) == 0 ) { // field is not set...
		return new LogVal(field.type, false);
	}

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

	case TYPE_TABLE:
	case TYPE_VECTOR:
		// First - common initialization
		// Then - initialization for table.
		// Then - initialization for vector.
		// Then - common stuff
		{
		// how many entries do we have...
		unsigned int length = 1;
		for ( unsigned int i = 0; i < s.size(); i++ )
			if ( s[i] == ',') length++;

		unsigned int pos = 0;
		
		if ( s.compare(empty_field) == 0 ) 
			length = 0;

		LogVal** lvals = new LogVal* [length];

		if ( field.type == TYPE_TABLE ) {
			val->val.set_val.vals = lvals;
			val->val.set_val.size = length;
		} else if ( field.type == TYPE_VECTOR ) {
			val->val.vector_val.vals = lvals;
			val->val.vector_val.size = length;
		} else {
			assert(false);
		}

		if ( length == 0 )
			break; //empty

		istringstream splitstream(s);
		while ( splitstream ) {
			string element;

			if ( !getline(splitstream, element, set_separator[0]) )
				break;

			if ( pos >= length ) {
				Error(Fmt("Internal error while parsing set. pos %d >= length %d. Element: %s", pos, length, element.c_str()));
				break;
			}

			LogVal* newval = EntryToVal(element, field.subType());
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

	string line;
	while ( GetLine(line ) ) {

		for ( map<int, Filter>::iterator it = filters.begin(); it != filters.end(); it++ ) {
		
			// split on tabs
			
			istringstream splitstream(line);
		
			LogVal** fields = new LogVal*[(*it).second.num_fields];
			//string string_fields[num_fields];

			unsigned int currTab = 0;
			unsigned int currField = 0;
			while ( splitstream ) {

				string s;
				if ( !getline(splitstream, s, separator[0]) )
					break;

				
				if ( currTab >= (*it).second.columnMap.size() ) {
					Error("Tabs in heading do not match tabs in data?");
					//disabled = true;
					return false;
				}

				FieldMapping currMapping = (*it).second.columnMap[currTab];
				currTab++;

				if ( currMapping.IsEmpty() ) {
					// well, that was easy
					continue;
				}

				if ( currField >= (*it).second.num_fields ) {
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

			if ( currField != (*it).second.num_fields ) {
				Error("curr_field != num_fields in DoUpdate. Columns in file do not match column definition.");
				return false;
			}


			SendEntry((*it).first, fields);

			for ( unsigned int i = 0; i < (*it).second.num_fields; i++ ) {
				delete fields[i];
			}
			delete [] fields;
		}

	}

	//file->clear(); // remove end of file evil bits
	//file->seekg(0, ios::beg); // and seek to start.

	for ( map<int, Filter>::iterator it = filters.begin(); it != filters.end(); it++ ) {
		EndCurrentSend((*it).first);
	}
	return true;
}
