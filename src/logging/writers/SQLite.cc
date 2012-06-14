// See the file "COPYING" in the main distribution directory for copyright.


#define USE_SQLITE 1
#ifdef USE_SQLITE

#include "config.h"
#include <string>
#include <errno.h>

#include "../../NetVar.h"

#include "../../threading/SerialTypes.h"

#include <vector>

#include "SQLite.h"

using namespace logging;
using namespace writer;
using threading::Value;
using threading::Field;

SQLite::SQLite(WriterFrontend* frontend) : WriterBackend(frontend)
	{
	set_separator_len = BifConst::LogSQLite::set_separator->Len();
	set_separator = new char[set_separator_len];
	memcpy(set_separator, BifConst::LogSQLite::set_separator->Bytes(),
	       set_separator_len);

	db = 0;
	}

SQLite::~SQLite()
	{
	if ( db != 0 ) 
		{
		sqlite3_close(db);
		db = 0;
		}
	}

string SQLite::GetTableType(int arg_type, int arg_subtype) {

	string type;

	switch ( arg_type ) {

	case TYPE_BOOL:
		type = "boolean";
		break;

	case TYPE_INT:
	case TYPE_COUNT:
	case TYPE_COUNTER:
	case TYPE_PORT:
		type = "integer";
		break;

		/*
	case TYPE_PORT:
		type = "VARCHAR(10)";
		break;
*/

	case TYPE_SUBNET:
	case TYPE_ADDR:
		type = "text"; // sqlite3 does not have a type for internet addresses
		break;

	case TYPE_TIME:
	case TYPE_INTERVAL:
	case TYPE_DOUBLE:
		type = "double precision";
		break;

	case TYPE_ENUM:
	case TYPE_STRING:
	case TYPE_FILE:
	case TYPE_FUNC:
		type = "TEXT";
		break;

	case TYPE_TABLE:
	case TYPE_VECTOR:
		type = "text"; // dirty - but sqlite does not directly support arrays. so - we just roll it into a ","-separated string I guess.
		//type = GetTableType(arg_subtype, 0) + "[]";
		break;

	default:
		Error(Fmt("unsupported field format %d ", arg_type));
		return "";
	}

	return type;
}


bool SQLite::checkError( int code ) 
	{
	if ( code != SQLITE_OK && code != SQLITE_DONE )
		{
		printf("SQLite call failed: %s\n", sqlite3_errmsg(db));
		Error(Fmt("SQLite call failed: %s", sqlite3_errmsg(db)));
		return true;
		}

	return false;	
	}

bool SQLite::DoInit(string path, int num_fields,
			    const Field* const * fields)
	{

	string fullpath = path+ ".sqlite";

	if ( checkError(sqlite3_open_v2(
					fullpath.c_str(),
					&db,
					SQLITE_OPEN_READWRITE | 
					SQLITE_OPEN_CREATE |
					SQLITE_OPEN_FULLMUTEX // perhaps change to nomutex
					,
					NULL)) )
		return false;

	string create = "CREATE TABLE IF NOT EXISTS "+path+" (\n"; // yes. using path here is stupid. open for better ideas.
		//"id SERIAL UNIQUE NOT NULL"; // SQLite has rowids, we do not need a counter here.

	for ( int i = 0; i < num_fields; ++i )
		{
			const Field* field = fields[i];
			
			if ( i != 0 ) 
				create += ",\n";

			string fieldname = fields[i]->name;
			replace( fieldname.begin(), fieldname.end(), '.', '_' ); // sqlite does not like "." in row names.
			create += fieldname;

			string type = GetTableType(field->type, field->subtype);

			create += " "+type;
			/* if ( !field->optional ) {
				create += " NOT NULL";
			} */

		}

	create += "\n);";

	//printf("Create: %s\n", create.c_str());

		{
		char *errorMsg = 0;
		int res = sqlite3_exec(db, create.c_str(), NULL, NULL, &errorMsg);
		if ( res != SQLITE_OK ) 
			{
			//printf("Error executing table creation statement: %s", errorMsg);
			Error(Fmt("Error executing table creation statement: %s", errorMsg));
			sqlite3_free(errorMsg);
			return false;
			}
		}


		{
		// create the prepared statement that will be re-used forever...

		string insert = "VALUES (";
		string names = "INSERT INTO "+path+" ( ";
	
		for ( int i = 0; i < num_fields; i++ )
			{
			bool ac = true;

			if ( i == 0 ) {
				ac = false;
			} else {
				names += ", ";
				insert += ", ";
			}

			insert += "?";	

			string fieldname = fields[i]->name;
			replace( fieldname.begin(), fieldname.end(), '.', '_' ); // sqlite does not like "." in row names.
			names += fieldname;

		}
		insert += ");";
		names += ") ";

		insert = names + insert;
		//printf("Prepared insert: %s\n\n", insert.c_str());

		if ( checkError(sqlite3_prepare_v2( db, insert.c_str(), insert.size()+1, &st, NULL )) )
			return false;
		}

	return true;
	}

bool SQLite::DoFlush()
	{
	return true;
	}

bool SQLite::DoFinish()
	{
	return true;
	}

// Format String
char* SQLite::FS(const char* format, ...) {
	char * buf;

	va_list al;
	va_start(al, format);
	int n = vasprintf(&buf, format, al);
	va_end(al);

	assert(n >= 0);

	return buf;
}

// this one is mainly ripped from Ascii.cc - with some adaptions.
void SQLite::ValToAscii(ODesc* desc, Value* val)
	{
	if ( ! val->present )
		{
			assert(false);
		}

	switch ( val->type ) {

	case TYPE_BOOL:
		desc->Add(val->val.int_val ? "T" : "F");
		break;

	case TYPE_INT:
		desc->Add(val->val.int_val);
		break;

	case TYPE_COUNT:
	case TYPE_COUNTER:
		desc->Add(val->val.uint_val);
		break;

	case TYPE_PORT:
		desc->Add(val->val.port_val.port);
		break;

	case TYPE_SUBNET:
		desc->Add(Render(val->val.subnet_val));
		break;

	case TYPE_ADDR:
		desc->Add(Render(val->val.addr_val));
		break;

	case TYPE_DOUBLE:
		// Rendering via Add() truncates trailing 0s after the
		// decimal point. The difference with TIME/INTERVAL is mainly
		// to keep the log format consistent.
		desc->Add(val->val.double_val);
		break;

	case TYPE_INTERVAL:
	case TYPE_TIME:
		// Rendering via Render() keeps trailing 0s after the decimal
		// point. The difference with DOUBLEis mainly to keep the log
		// format consistent.
		desc->Add(Render(val->val.double_val));
		break;

	case TYPE_ENUM:
	case TYPE_STRING:
	case TYPE_FILE:
	case TYPE_FUNC:
		{
		int size = val->val.string_val->size();
		const char* data = val->val.string_val->data();

		if ( size )
			desc->AddN(data, size);

		break;
		}

	case TYPE_TABLE:
	case TYPE_VECTOR:
		assert(false);
		// this would mean that we have a table/vector inside a table/vector.
		// that is not possible and shoulr have been caught way earlier.

	default:
		// there may not be any types that we do not know here.
		assert(false);
	}

	}


int SQLite::AddParams(Value* val, int pos)
	{

	if ( ! val->present )
		{
			return sqlite3_bind_null(st, pos);
		}

	switch ( val->type ) {

	case TYPE_BOOL:
		return sqlite3_bind_int(st, pos, val->val.int_val ? 1 : 0 );

	case TYPE_INT:
		return sqlite3_bind_int(st, pos, val->val.int_val);

	case TYPE_COUNT:
	case TYPE_COUNTER:
		return sqlite3_bind_int(st, pos, val->val.uint_val);

	case TYPE_PORT:
		return sqlite3_bind_int(st, pos, val->val.port_val.port);

	case TYPE_SUBNET:
		{
		string out = Render(val->val.subnet_val).c_str();
		return sqlite3_bind_text(st, pos, out.data(), out.size(), SQLITE_TRANSIENT);
		}

	case TYPE_ADDR:
		{
		string out = Render(val->val.addr_val).c_str();			
		return sqlite3_bind_text(st, pos, out.data(), out.size(), SQLITE_TRANSIENT);
		}

	case TYPE_TIME:
	case TYPE_INTERVAL:
	case TYPE_DOUBLE:
		return sqlite3_bind_double(st, pos, val->val.double_val);

	case TYPE_ENUM:
	case TYPE_STRING:
	case TYPE_FILE:
	case TYPE_FUNC:
		{
		if ( ! val->val.string_val->size() || val->val.string_val->size() == 0 ) 
			return sqlite3_bind_null(st, pos);

		return sqlite3_bind_text(st, pos, val->val.string_val->data(), val->val.string_val->size(), SQLITE_TRANSIENT); // FIXME who deletes this
		}

	case TYPE_TABLE:
		{
		ODesc desc;
		desc.Clear();		
		desc.AddEscapeSequence(set_separator, set_separator_len);

		for ( int j = 0; j < val->val.set_val.size; j++ )
			{
			if ( j > 0 )
				desc.AddRaw(set_separator, set_separator_len);

			ValToAscii(&desc, val->val.set_val.vals[j]);
			}


		return sqlite3_bind_text(st, pos, (const char*) desc.Bytes(), desc.Len(), SQLITE_TRANSIENT);
		}

	case TYPE_VECTOR:
		{
		ODesc desc;
		desc.Clear();		
		desc.AddEscapeSequence(set_separator, set_separator_len);

		for ( int j = 0; j < val->val.vector_val.size; j++ )
			{
			if ( j > 0 )
				desc.AddRaw(set_separator, set_separator_len);

			ValToAscii(&desc, val->val.vector_val.vals[j]);
			}


		return sqlite3_bind_text(st, pos, (const char*) desc.Bytes(), desc.Len(), SQLITE_TRANSIENT);
		}



	default:
		Error(Fmt("unsupported field format %d", val->type ));
		return 0;
	}
	}

bool SQLite::DoWrite(int num_fields, const Field* const * fields, Value** vals)
	{

	// bind parameters
	for ( int i = 0; i < num_fields; i++ ) 
		{
		if ( checkError(AddParams(vals[i], i+1)) ) 
			return false;
		}

	// execute query
	if ( checkError(sqlite3_step(st)) )
		return false;

	// clean up and make ready for next query execution
	if ( checkError(sqlite3_clear_bindings(st)) ) 
		return false;

	if ( checkError(sqlite3_reset(st)) )
		return false;


	return true;
	}

bool SQLite::DoRotate(string rotated_path, double open, double close, bool terminating)
	{
	return true;
	}

bool SQLite::DoSetBuf(bool enabled)
	{
	// Nothing to do.
	return true;
	}

#endif /* USE_SQLITE */
