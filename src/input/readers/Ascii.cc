// See the file "COPYING" in the main distribution directory for copyright.

#include "Ascii.h"
#include "NetVar.h"

#include <fstream>
#include <sstream>

#include "../../threading/SerializationTypes.h"

#define MANUAL 0
#define REREAD 1
#define STREAM 2

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace input::reader;
using threading::Value;
using threading::Field;


FieldMapping::FieldMapping(const string& arg_name, const TypeTag& arg_type, int arg_position) 
	: name(arg_name), type(arg_type)
{
	position = arg_position;
	secondary_position = -1;
}

FieldMapping::FieldMapping(const string& arg_name, const TypeTag& arg_type, const TypeTag& arg_subtype, int arg_position) 
	: name(arg_name), type(arg_type), subtype(arg_subtype)
{
	position = arg_position;
	secondary_position = -1;
}

FieldMapping::FieldMapping(const FieldMapping& arg) 
	: name(arg.name), type(arg.type), subtype(arg.subtype)
{
	position = arg.position;
	secondary_position = arg.secondary_position;
}

FieldMapping FieldMapping::subType() {
	return FieldMapping(name, subtype, position);
}

Ascii::Ascii(ReaderFrontend *frontend) : ReaderBackend(frontend)
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

Ascii::~Ascii()
{
	DoFinish();

}

void Ascii::DoFinish()
{
	filters.empty();
	if ( file != 0 ) {
		file->close();
		delete(file);
		file = 0;
	}
}

bool Ascii::DoInit(string path, int arg_mode)
{
	started = false;
	fname = path;
	mode = arg_mode;
	mtime = 0;
	
	if ( ( mode != MANUAL ) && (mode != REREAD) && ( mode != STREAM ) ) {
		Error(Fmt("Unsupported read mode %d for source %s", mode, path.c_str()));
		return false;
	} 	

	file = new ifstream(path.c_str());
	if ( !file->is_open() ) {
		Error(Fmt("Init: cannot open %s", fname.c_str()));
		return false;
	}
	
	if ( ReadHeader(false) == false ) {
		Error(Fmt("Init: cannot open %s; headers are incorrect", fname.c_str()));
		file->close();
		return false;
	}

	return true;
}

bool Ascii::DoStartReading() {
	if ( started == true ) {
		Error("Started twice");
		return false;
	}	

	started = true;
	switch ( mode ) {
		case MANUAL:
		case REREAD:
		case STREAM:
			DoUpdate();
			break;
		default:
			assert(false);
	}

	return true;
}

bool Ascii::DoAddFilter( int id, int arg_num_fields, const Field* const* fields ) {
	if ( HasFilter(id) ) {
		return false; // no, we don't want to add this a second time
	}

	Filter f;
	f.num_fields = arg_num_fields;
	f.fields = fields;

	filters[id] = f;

	return true;
}

bool Ascii::DoRemoveFilter ( int id ) {
	if (!HasFilter(id) ) {
		return false;
	}

	assert ( filters.erase(id) == 1 );

	return true;
}	


bool Ascii::HasFilter(int id) {
	map<int, Filter>::iterator it = filters.find(id);	
	if ( it == filters.end() ) {
		return false;
	}
	return true;
}


bool Ascii::ReadHeader(bool useCached) {
	// try to read the header line...
	string line;
	map<string, uint32_t> fields;

	if ( !useCached ) {
		if ( !GetLine(line) ) {
			Error("could not read first line");
			return false;
		}



		headerline = line;

	} else {
		line = headerline;
	}
	
	// construct list of field names.
	istringstream splitstream(line);
	int pos=0;
	while ( splitstream ) {
		string s;
		if ( !getline(splitstream, s, separator[0]))
			break;

		fields[s] = pos;
		pos++;
	}

	//printf("Updating fields from description %s\n", line.c_str());
	for ( map<int, Filter>::iterator it = filters.begin(); it != filters.end(); it++ ) {
		(*it).second.columnMap.clear();
			
		for ( unsigned int i = 0; i < (*it).second.num_fields; i++ ) {
			const Field* field = (*it).second.fields[i];
			
			map<string, uint32_t>::iterator fit = fields.find(field->name);	
			if ( fit == fields.end() ) {
				Error(Fmt("Did not find requested field %s in input data file.", field->name.c_str()));
				return false;
			}
	

			FieldMapping f(field->name, field->type, field->subtype, fields[field->name]);
			if ( field->secondary_name != "" ) {
				map<string, uint32_t>::iterator fit2 = fields.find(field->secondary_name);					
				if ( fit2 == fields.end() ) {
					Error(Fmt("Could not find requested port type field %s in input data file.", field->secondary_name.c_str()));
					return false;
				}
				f.secondary_position = fields[field->secondary_name];
			}
			(*it).second.columnMap.push_back(f);
		}

	}
	
	// well, that seems to have worked...
	return true;
}

bool Ascii::GetLine(string& str) {
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

TransportProto Ascii::StringToProto(const string &proto) {
	if ( proto == "unknown" ) {
		return TRANSPORT_UNKNOWN;
	} else if ( proto == "tcp" ) {
		return TRANSPORT_TCP;
	} else if ( proto == "udp" ) {
		return TRANSPORT_UDP;
	} else if ( proto == "icmp" ) {
		return TRANSPORT_ICMP;
	}

	//assert(false);
	
	reporter->Error("Tried to parse invalid/unknown protocol: %s", proto.c_str());

	return TRANSPORT_UNKNOWN;
}

Value* Ascii::EntryToVal(string s, FieldMapping field) {

	Value* val = new Value(field.type, true);

	if ( s.compare(unset_field) == 0 ) { // field is not set...
		return new Value(field.type, false);
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
		val->val.uint_val = atoi(s.c_str());
		break;

	case TYPE_PORT:
		val->val.port_val.port = atoi(s.c_str());
		val->val.port_val.proto = TRANSPORT_UNKNOWN;
		break;

	case TYPE_SUBNET: {
		int pos = s.find("/");
		string width = s.substr(pos+1);
		val->val.subnet_val.width = atoi(width.c_str());
		string addr = s.substr(0, pos);
		s = addr;
#ifdef BROv6
		if ( s.find(':') != s.npos ) {
			uint32* addr = new uint32[4];
			if ( inet_pton(AF_INET6, s.c_str(), addr) <= 0 ) {
				Error(Fmt("Bad IPv6 address: %s", s.c_str()));
				val->val.subnet_val.net[0] = val->val.subnet_val.net[1] = val->val.subnet_val.net[2] = val->val.subnet_val.net[3] = 0;
			}
			copy_addr(val->val.subnet_val.net, addr);
			delete addr;
		} else {
			val->val.subnet_val.net[0] = val->val.subnet_val.net[1] = val->val.subnet_val.net[2] = 0;
			if ( inet_aton(s.c_str(), &(val->val.subnet_val.net[3])) <= 0 ) {
				Error(Fmt("Bad addres: %s", s.c_str()));
		       		val->val.subnet_val.net[3] = 0;
			}
		}
#else
		if ( inet_aton(s.c_str(), (in_addr*) &(val->val.subnet_val.net)) <= 0 ) {
			Error(Fmt("Bad addres: %s", s.c_str()));
			val->val.subnet_val.net = 0;
		}
#endif
		break;

		}
	case TYPE_ADDR: {
		// NOTE: dottet_to_addr BREAKS THREAD SAFETY! it uses reporter.
		// Solve this some other time....
#ifdef BROv6
		if ( s.find(':') != s.npos ) {
			uint32* addr = dotted_to_addr6(s.c_str());
			copy_addr(val->val.addr_val, addr);
			delete addr;
		} else {
			val->val.addr_val[0] = val->val.addr_val[1] = val->val.addr_val[2] = 0;
		       	val->val.addr_val[3] = dotted_to_addr(s.c_str());
		}
#else
		uint32 t = dotted_to_addr(s.c_str());
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

		Value** lvals = new Value* [length];

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

			Value* newval = EntryToVal(element, field.subType());
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
bool Ascii::DoUpdate() {
	switch ( mode ) {
		case REREAD:
			// check if the file has changed
			struct stat sb;
			if ( stat(fname.c_str(), &sb) == -1 ) {
				Error(Fmt("Could not get stat for %s", fname.c_str()));
				return false;
			}

			if ( sb.st_mtime <= mtime ) {
				// no change
				return true;
			}

			mtime = sb.st_mtime;
			// file changed. reread.

			// fallthrough
		case MANUAL:
		case STREAM:

			// dirty, fix me. (well, apparently after trying seeking, etc - this is not that bad)
			if ( file && file->is_open() ) {
				if ( mode == STREAM ) {
					file->clear(); // remove end of file evil bits
					if ( !ReadHeader(true) )  // in case filters changed
					{
						return false; // header reading failed
					}
					break;
				}
				file->close();
			}
			file = new ifstream(fname.c_str());
			if ( !file->is_open() ) {
				Error(Fmt("cannot open %s", fname.c_str()));
				return false;
			}


			if ( ReadHeader(false) == false ) {
				return false;
			}

			break;
		default:
			assert(false);

	}


	// 
	
	// file->seekg(0, ios::beg); // do not forget clear.



	string line;
	while ( GetLine(line ) ) {
		// split on tabs
		istringstream splitstream(line);

		map<int, string> stringfields;
		int pos = 0;
		while ( splitstream ) {
			string s;
			if ( !getline(splitstream, s, separator[0]) )
				break;

			stringfields[pos] = s;
			pos++;
		}

		pos--; // for easy comparisons of max element.

		for ( map<int, Filter>::iterator it = filters.begin(); it != filters.end(); it++ ) {
		
			Value** fields = new Value*[(*it).second.num_fields];

			int fpos = 0;
			for ( vector<FieldMapping>::iterator fit = (*it).second.columnMap.begin();
				fit != (*it).second.columnMap.end();
				fit++ ){


				if ( (*fit).position > pos || (*fit).secondary_position > pos ) {
					Error(Fmt("Not enough fields in line %s. Found %d fields, want positions %d and %d", line.c_str(), pos,  (*fit).position, (*fit).secondary_position));
					return false;
				}

				Value* val = EntryToVal(stringfields[(*fit).position], *fit);
				if ( val == 0 ) {
					Error("Could not convert String value to Val");
					return false;
				}
				
				if ( (*fit).secondary_position != -1 ) {
					// we have a port definition :)
					assert(val->type == TYPE_PORT ); 
					//	Error(Fmt("Got type %d != PORT with secondary position!", val->type));

					val->val.port_val.proto = StringToProto(stringfields[(*fit).secondary_position]);
				}

				fields[fpos] = val;

				fpos++;
			}

			//printf("fpos: %d, second.num_fields: %d\n", fpos, (*it).second.num_fields);
			assert ( (unsigned int) fpos == (*it).second.num_fields );

			if ( mode == STREAM ) {
				Put((*it).first, fields);
			} else {
				SendEntry((*it).first, fields);
			}

			/* Do not do this, ownership changes to other thread 
			 * for ( unsigned int i = 0; i < (*it).second.num_fields; i++ ) {
				delete fields[i];
			}
			delete [] fields;
			*/
		}

	}


	//file->clear(); // remove end of file evil bits
	//file->seekg(0, ios::beg); // and seek to start.

	if ( mode != STREAM ) {
		for ( map<int, Filter>::iterator it = filters.begin(); it != filters.end(); it++ ) {
			EndCurrentSend((*it).first);
		}
	}

	return true;
}

bool Ascii::DoHeartbeat(double network_time, double current_time)
{
	ReaderBackend::DoHeartbeat(network_time, current_time);

	switch ( mode ) {
		case MANUAL:
			// yay, we do nothing :)
			break;
		case REREAD:
		case STREAM:
			Update(); // call update and not DoUpdate, because update actually checks disabled.
			break;
		default:
			assert(false);
	}

	return true;
}

