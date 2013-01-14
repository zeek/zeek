// See the file "COPYING" in the main distribution directory for copyright.

#include "config.h"

#ifdef USE_SQLITE

#include "SQLite.h"
#include "NetVar.h"

#include <fstream>
#include <sstream>

#include "../../threading/SerialTypes.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace input::reader;
using threading::Value;
using threading::Field;


SQLite::SQLite(ReaderFrontend *frontend) : ReaderBackend(frontend)
	{
	io = new AsciiInputOutput(this, AsciiInputOutput::SeparatorInfo());
	}

SQLite::~SQLite()
	{
	DoClose();
	delete io;
	}

void SQLite::DoClose()
	{
	if ( db != 0 ) 
		{
		sqlite3_close(db);
		db = 0;
		}
	}

bool SQLite::checkError( int code ) 
	{
	if ( code != SQLITE_OK && code != SQLITE_DONE )
		{
		Error(Fmt("SQLite call failed: %s", sqlite3_errmsg(db)));
		return true;
		}

	return false;	
	}

bool SQLite::DoInit(const ReaderInfo& info, int arg_num_fields, const threading::Field* const* arg_fields)
	{
	started = false;

	string fullpath(info.source);
	fullpath.append(".sqlite");
	
	string dbname;
	map<const char*, const char*>::const_iterator it = info.config.find("dbname");	
	if ( it == info.config.end() ) 
		{
		MsgThread::Info(Fmt("dbname configuration option not found. Defaulting to source %s", info.source));
		Error(Fmt("dbname configuration option not found. Defaulting to source %s", info.source));
		dbname = info.source;
		} 
	else 
		dbname = it->second;

	string query;
	it = info.config.find("query");	
	if ( it == info.config.end() ) 
		{
		Error(Fmt("No query specified when setting up SQLite data source. Aborting.", info.source));
		return false;
		} 
	else 
		query = it->second;

	if ( checkError(sqlite3_open_v2(
					fullpath.c_str(),
					&db,
					SQLITE_OPEN_READWRITE | 
					SQLITE_OPEN_FULLMUTEX // perhaps change to nomutex
					,
					NULL)) )
		return false;


	num_fields = arg_num_fields;
	fields = arg_fields;

	// create the prepared select statement that we will re-use forever...
	if ( checkError(sqlite3_prepare_v2( db, query.c_str(), query.size()+1, &st, NULL )) )
		{
		return false;
		}

	
	DoUpdate();

	return true;
	}

Value* SQLite::EntryToVal(sqlite3_stmt *st, const threading::Field *field, int pos)
	{
	
	if ( sqlite3_column_type(st, pos ) == SQLITE_NULL ) 
		return new Value(field->type, false);

	Value* val = new Value(field->type, true);
			
	switch ( field->type ) {
	case TYPE_ENUM:
	case TYPE_STRING:
		{
		const char *text = (const char*) sqlite3_column_text(st, pos);
		int length = sqlite3_column_bytes(st, pos);

		char *out = new char[length];
		memcpy(out, text, length);

		val->val.string_val.length = length;
		val->val.string_val.data = out;
		break;
		}

	case TYPE_BOOL:
		{
		if ( sqlite3_column_type(st, pos) != SQLITE_INTEGER ) {
			Error("Invalid data type for boolean - expected Integer");
			return 0;
		}

		int res = sqlite3_column_int(st, pos);

		if ( res == 0 || res == 1 ) 
			val->val.int_val = res;
		else
			{	
			Error(Fmt("Invalid value for boolean: %d", res));
			return 0;
			}
		break;
		}

	case TYPE_INT:
		val->val.int_val = sqlite3_column_int64(st, pos);
		break;

	case TYPE_DOUBLE:
	case TYPE_TIME:
	case TYPE_INTERVAL:
		val->val.double_val = sqlite3_column_double(st, pos);
		break;

	case TYPE_COUNT:
	case TYPE_COUNTER:
		val->val.uint_val = sqlite3_column_int64(st, pos);
		break;

	case TYPE_PORT:
		val->val.port_val.port = sqlite3_column_int(st, pos);
		val->val.port_val.proto = TRANSPORT_UNKNOWN;
		break;

	case TYPE_SUBNET: {
		const char *text = (const char*) sqlite3_column_text(st, pos);
		string s(text, sqlite3_column_bytes(st, pos));
		int pos = s.find("/");
		int width = atoi(s.substr(pos+1).c_str());
		string addr = s.substr(0, pos);

		val->val.subnet_val.prefix = io->StringToAddr(addr);
		val->val.subnet_val.length = width;		
		break;

		}
	case TYPE_ADDR: 
		{
		const char *text = (const char*) sqlite3_column_text(st, pos);
		string s(text, sqlite3_column_bytes(st, pos));			
		val->val.addr_val = io->StringToAddr(s);			  
		break;
		}

	case TYPE_TABLE:
	case TYPE_VECTOR:
		assert(false);
		/* 
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

		if ( field->type == TYPE_TABLE ) 
			{
			val->val.set_val.vals = lvals;
			val->val.set_val.size = length;
			} 
		else if ( field->type == TYPE_VECTOR ) 
			{
			val->val.vector_val.vals = lvals;
			val->val.vector_val.size = length;
		else 
			assert(false);

		if ( length == 0 )
			break; //empty

		istringstream splitstream(s);
		while ( splitstream ) 
			{
			string element;

			if ( !getline(splitstream, element, ',') )
				break;

			if ( pos >= length ) 
				{
				Error(Fmt("Internal error while parsing set. pos %d >= length %d. Element: %s", pos, length, element.c_str()));
				break;
				}

			Field* newfield = new Field(*field);
			newfield->type = field->subtype;
			Value* newval = EntryToVal(element, newfield);
			delete(newfield);
			if ( newval == 0 ) 
				{
				Error("Error while reading set");
				return 0;
				}
			lvals[pos] = newval;

			pos++;
	
			}


		if ( pos != length ) 
			{
			Error("Internal error while parsing set: did not find all elements");
			return 0;
			}

		break;
		}
		*/


	default:
		Error(Fmt("unsupported field format %d", field->type));
		return 0;
	}	

	return val;

	}

bool SQLite::DoUpdate() 
	{

	int numcolumns = sqlite3_column_count(st);

	/* This can happen legitimately I think...
	if ( numcolumns != num_fields ) 
		{
		Error(Fmt("SQLite query returned %d results, but input framework expected %d. Aborting", numcolumns, num_fields));
		return false;
		}
	*/
	
	int *mapping = new int [num_fields];
	// first set them all to -1
	for ( unsigned int i = 0; i < num_fields; ++i ) {
		mapping[i] = -1;
	}

	for ( unsigned int i = 0; i < numcolumns; ++i ) 
		{
		const char *name = sqlite3_column_name(st, i);

		for ( unsigned j = 0; j < num_fields; j++ ) {
			if ( strcmp(fields[j]->name, name) == 0 ) {
				if ( mapping[j] != -1 ) 
					{
					Error(Fmt("SQLite statement returns several columns with name %s! Cannot decide which to choose, aborting", name));
					return false;
					}

				mapping[j] = i;
				break;
			}
		}

		}
	
	for ( unsigned int i = 0; i < num_fields; ++i ) {
		if ( mapping[i] == -1 ) 
			{
			Error(Fmt("Required field %s not found after SQLite statement", fields[i]->name));
			return false;
			}
	}

	int errorcode;
	while ( ( errorcode = sqlite3_step(st)) == SQLITE_ROW ) 
		{
		Value** ofields = new Value*[num_fields];

		for ( unsigned int j = 0; j < num_fields; ++j) 
			{

			ofields[j] = EntryToVal(st, fields[j], mapping[j]);
			if ( ofields[j] == 0 ) {
				return false;
			} 

			}

		SendEntry(ofields);
		}

	if ( checkError(errorcode) ) // check the last error code returned by sqlite
		return false;


	EndCurrentSend();

	delete (mapping);

	if ( checkError(sqlite3_reset(st)) )
		return false;	

	return true;
	}

#endif /* USE_SQLITE */
