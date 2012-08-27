// See the file "COPYING" in the main distribution directory for copyright.

#include "Ascii.h"
#include "NetVar.h"

#include <fstream>
#include <sstream>

#include "../../threading/SerialTypes.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

using namespace input::reader;
using threading::Value;
using threading::Field;

FieldMapping::FieldMapping(const string& arg_name, const TypeTag& arg_type, int arg_position)
	: name(arg_name), type(arg_type)
	{
	position = arg_position;
	secondary_position = -1;
	present = true;
	}

FieldMapping::FieldMapping(const string& arg_name, const TypeTag& arg_type,
		const TypeTag& arg_subtype, int arg_position)
	: name(arg_name), type(arg_type), subtype(arg_subtype)
	{
	position = arg_position;
	secondary_position = -1;
	present = true;
	}

FieldMapping::FieldMapping(const FieldMapping& arg)
	: name(arg.name), type(arg.type), subtype(arg.subtype), present(arg.present)
	{
	position = arg.position;
	secondary_position = arg.secondary_position;
	}

FieldMapping FieldMapping::subType()
	{
	return FieldMapping(name, subtype, position);
	}

Ascii::Ascii(ReaderFrontend *frontend) : ReaderBackend(frontend)
	{
	file = 0;

	separator.assign( (const char*) BifConst::InputAscii::separator->Bytes(),
			  BifConst::InputAscii::separator->Len());

	if ( separator.size() != 1 )
		Error("separator length has to be 1. Separator will be truncated.");

	set_separator.assign( (const char*) BifConst::InputAscii::set_separator->Bytes(),
		              BifConst::InputAscii::set_separator->Len());

	if ( set_separator.size() != 1 )
		Error("set_separator length has to be 1. Separator will be truncated.");

	empty_field.assign( (const char*) BifConst::InputAscii::empty_field->Bytes(),
			    BifConst::InputAscii::empty_field->Len());

	unset_field.assign( (const char*) BifConst::InputAscii::unset_field->Bytes(),
			    BifConst::InputAscii::unset_field->Len());
}

Ascii::~Ascii()
	{
	DoClose();
	}

void Ascii::DoClose()
	{
	if ( file != 0 )
		{
		file->close();
		delete(file);
		file = 0;
		}
	}

bool Ascii::DoInit(const ReaderInfo& info, int num_fields, const Field* const* fields)
	{
	mtime = 0;

	file = new ifstream(info.source);
	if ( ! file->is_open() )
		{
		Error(Fmt("Init: cannot open %s", info.source));
		delete(file);
		file = 0;
		return false;
		}

	if ( ReadHeader(false) == false )
		{
		Error(Fmt("Init: cannot open %s; headers are incorrect", info.source));
		file->close();
		delete(file);
		file = 0;
		return false;
		}

	DoUpdate();

	return true;
	}


bool Ascii::ReadHeader(bool useCached)
	{
	// try to read the header line...
	string line;
	map<string, uint32_t> ifields;

	if ( ! useCached )
		{
		if ( ! GetLine(line) )
			{
			Error("could not read first line");
			return false;
			}

		headerline = line;
		}

	else
		line = headerline;

	// construct list of field names.
	istringstream splitstream(line);
	int pos=0;
	while ( splitstream )
		{
		string s;
		if ( ! getline(splitstream, s, separator[0]))
			break;

		ifields[s] = pos;
		pos++;
		}

	// printf("Updating fields from description %s\n", line.c_str());
	columnMap.clear();

	for ( int i = 0; i < NumFields(); i++ )
		{
		const Field* field = Fields()[i];

		map<string, uint32_t>::iterator fit = ifields.find(field->name);
		if ( fit == ifields.end() )
			{
			if ( field->optional )
				{
				// we do not really need this field. mark it as not present and always send an undef back.
				FieldMapping f(field->name, field->type, field->subtype, -1);
				f.present = false;
				columnMap.push_back(f);
				continue;
				}

			Error(Fmt("Did not find requested field %s in input data file %s.",
				  field->name, Info().source));
			return false;
			}


		FieldMapping f(field->name, field->type, field->subtype, ifields[field->name]);

		if ( field->secondary_name && strlen(field->secondary_name) != 0 )
			{
			map<string, uint32_t>::iterator fit2 = ifields.find(field->secondary_name);
			if ( fit2 == ifields.end() )
				{
				Error(Fmt("Could not find requested port type field %s in input data file.",
					  field->secondary_name));
				return false;
				}

			f.secondary_position = ifields[field->secondary_name];
			}

		columnMap.push_back(f);
		}


	// well, that seems to have worked...
	return true;
	}

bool Ascii::GetLine(string& str)
	{
	while ( getline(*file, str) )
       		{
		if ( str[0] != '#' )
			return true;

		if ( ( str.length() > 8 ) && ( str.compare(0,7, "#fields") == 0 ) && ( str[7] == separator[0] ) )
			{
			str = str.substr(8);
			return true;
			}
		}

	return false;
	}

bool Ascii::CheckNumberError(const string& s, const char * end)
	{
	// Do this check first, before executing s.c_str() or similar.
	// otherwise the value to which *end is pointing at the moment might
	// be gone ...
	bool endnotnull =  (*end != '\0');

	if ( s.length() == 0 )
		{
		Error("Got empty string for number field");
		return true;
		}

	if ( end == s.c_str() ) {
		Error(Fmt("String '%s' contained no parseable number", s.c_str()));
		return true;
	}

	if ( endnotnull )
		Warning(Fmt("Number '%s' contained non-numeric trailing characters. Ignored trailing characters '%s'", s.c_str(), end));

	if ( errno == EINVAL )
		{
		Error(Fmt("String '%s' could not be converted to a number", s.c_str()));
		return true;
		}

	else if ( errno == ERANGE )
		{
		Error(Fmt("Number '%s' out of supported range.", s.c_str()));
		return true;
		}

	return false;
	}


Value* Ascii::EntryToVal(string s, FieldMapping field)
	{
	if ( s.compare(unset_field) == 0 )  // field is not set...
		return new Value(field.type, false);

	Value* val = new Value(field.type, true);
	char* end = 0;
	errno = 0;

	switch ( field.type ) {
	case TYPE_ENUM:
	case TYPE_STRING:
		s = get_unescaped_string(s);
		val->val.string_val.length = s.size();
		val->val.string_val.data = copy_string(s.c_str());
		break;

	case TYPE_BOOL:
		if ( s == "T" )
			val->val.int_val = 1;
		else if ( s == "F" )
			val->val.int_val = 0;
		else
			{
			Error(Fmt("Field: %s Invalid value for boolean: %s",
				  field.name.c_str(), s.c_str()));
			return 0;
			}
		break;

	case TYPE_INT:
		val->val.int_val = strtoll(s.c_str(), &end, 10);
		if ( CheckNumberError(s, end) )
			return 0;
		break;

	case TYPE_DOUBLE:
	case TYPE_TIME:
	case TYPE_INTERVAL:
		val->val.double_val = strtod(s.c_str(), &end);
		if ( CheckNumberError(s, end) )
			return 0;
		break;

	case TYPE_COUNT:
	case TYPE_COUNTER:
		val->val.uint_val = strtoull(s.c_str(), &end, 10);
		if ( CheckNumberError(s, end) )
			return 0;
		break;

	case TYPE_PORT:
		val->val.port_val.port = strtoull(s.c_str(), &end, 10);
		if ( CheckNumberError(s, end) )
			return 0;

		val->val.port_val.proto = TRANSPORT_UNKNOWN;
		break;

	case TYPE_SUBNET:
		{
		s = get_unescaped_string(s);
		size_t pos = s.find("/");
		if ( pos == s.npos )
			{
			Error(Fmt("Invalid value for subnet: %s", s.c_str()));
			return 0;
			}

		uint8_t width = (uint8_t) strtol(s.substr(pos+1).c_str(), &end, 10);

		if ( CheckNumberError(s, end) )
			return 0;

		string addr = s.substr(0, pos);

		val->val.subnet_val.prefix = StringToAddr(addr);
		val->val.subnet_val.length = width;
		break;
		}

	case TYPE_ADDR:
		s = get_unescaped_string(s);
		val->val.addr_val = StringToAddr(s);
		break;

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
			{
			if ( s[i] == set_separator[0] )
				length++;
			}

		unsigned int pos = 0;

		if ( s.compare(empty_field) == 0 )
			length = 0;

		Value** lvals = new Value* [length];

		if ( field.type == TYPE_TABLE )
			{
			val->val.set_val.vals = lvals;
			val->val.set_val.size = length;
			}

		else if ( field.type == TYPE_VECTOR )
			{
			val->val.vector_val.vals = lvals;
			val->val.vector_val.size = length;
			}

		else
			assert(false);

		if ( length == 0 )
			break; //empty

		istringstream splitstream(s);
		while ( splitstream )
			{
			string element;

			if ( ! getline(splitstream, element, set_separator[0]) )
				break;

			if ( pos >= length )
				{
				Error(Fmt("Internal error while parsing set. pos %d >= length %d."
				          " Element: %s", pos, length, element.c_str()));
				break;
				}

			Value* newval = EntryToVal(element, field.subType());
			if ( newval == 0 )
				{
				Error("Error while reading set");
				return 0;
				}

			lvals[pos] = newval;

			pos++;
			}

		// Test if the string ends with a set_separator... or if the
		// complete string is empty. In either of these cases we have
		// to push an empty val on top of it.
		if ( s.empty() || *s.rbegin() == set_separator[0] )
			{
			lvals[pos] = EntryToVal("", field.subType());
			if ( lvals[pos] == 0 )
				{
				Error("Error while trying to add empty set element");
				return 0;
				}

			pos++;
			}

		if ( pos != length )
			{
			Error(Fmt("Internal error while parsing set: did not find all elements: %s", s.c_str()));
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
bool Ascii::DoUpdate()
	{
	switch ( Info().mode ) {
		case MODE_REREAD:
			{
			// check if the file has changed
			struct stat sb;
			if ( stat(Info().source, &sb) == -1 )
				{
				Error(Fmt("Could not get stat for %s", Info().source));
				return false;
				}

			if ( sb.st_mtime <= mtime ) // no change
				return true;

			mtime = sb.st_mtime;
			// file changed. reread.

			// fallthrough
			}

		case MODE_MANUAL:
		case MODE_STREAM:
			{
			// dirty, fix me. (well, apparently after trying seeking, etc
			// - this is not that bad)
			if ( file && file->is_open() )
				{
				if ( Info().mode == MODE_STREAM )
					{
					file->clear(); // remove end of file evil bits
					if ( !ReadHeader(true) )
						return false; // header reading failed

					break;
					}

				file->close();
				delete file;
				file = 0;
				}

			file = new ifstream(Info().source);
			if ( ! file->is_open() )
				{
				Error(Fmt("cannot open %s", Info().source));
				return false;
				}

			if ( ReadHeader(false) == false )
				{
				return false;
				}

			break;
			}

		default:
			assert(false);

		}

	string line;
	while ( GetLine(line ) )
		{
		// split on tabs
		bool error = false;
		istringstream splitstream(line);

		map<int, string> stringfields;
		int pos = 0;
		while ( splitstream )
			{
			string s;
			if ( ! getline(splitstream, s, separator[0]) )
				break;

			stringfields[pos] = s;
			pos++;
			}

		pos--; // for easy comparisons of max element.

		Value** fields = new Value*[NumFields()];

		int fpos = 0;
		for ( vector<FieldMapping>::iterator fit = columnMap.begin();
			fit != columnMap.end();
			fit++ )
			{

			if ( ! fit->present )
				{
				// add non-present field
				fields[fpos] =  new Value((*fit).type, false);
				fpos++;
				continue;
				}

			assert(fit->position >= 0 );

			if ( (*fit).position > pos || (*fit).secondary_position > pos )
				{
				Error(Fmt("Not enough fields in line %s. Found %d fields, want positions %d and %d",
					  line.c_str(), pos,  (*fit).position, (*fit).secondary_position));
				return false;
				}

			Value* val = EntryToVal(stringfields[(*fit).position], *fit);
			if ( val == 0 )
				{
				Error(Fmt("Could not convert line '%s' to Val. Ignoring line.", line.c_str()));
				error = true;
				break;
				}

			if ( (*fit).secondary_position != -1 )
				{
				// we have a port definition :)
				assert(val->type == TYPE_PORT );
				//	Error(Fmt("Got type %d != PORT with secondary position!", val->type));

				val->val.port_val.proto = StringToProto(stringfields[(*fit).secondary_position]);
				}

			fields[fpos] = val;

			fpos++;
			}

		if ( error )
			{
			// Encountered non-fatal error, ignoring line. But
			// first, delete all successfully read fields and the
			// array structure.

			for ( int i = 0; i < fpos; i++ )
				delete fields[fpos];

			delete [] fields;
			continue;
			}

		//printf("fpos: %d, second.num_fields: %d\n", fpos, (*it).second.num_fields);
		assert ( fpos == NumFields() );

		if ( Info().mode  == MODE_STREAM )
			Put(fields);
		else
			SendEntry(fields);
		}

	if ( Info().mode != MODE_STREAM )
		EndCurrentSend();

	return true;
	}

bool Ascii::DoHeartbeat(double network_time, double current_time)
{
	switch ( Info().mode  ) {
		case MODE_MANUAL:
			// yay, we do nothing :)
			break;

		case MODE_REREAD:
		case MODE_STREAM:
			Update(); // call update and not DoUpdate, because update
				  // checks disabled.
			break;

		default:
			assert(false);
	}

	return true;
	}

