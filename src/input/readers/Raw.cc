// See the file "COPYING" in the main distribution directory for copyright.

#include "Raw.h"
#include "NetVar.h"

#include <fstream>
#include <sstream>

#include "../../threading/SerialTypes.h"
#include "../fdstream.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>

using namespace input::reader;
using threading::Value;
using threading::Field;

Raw::Raw(ReaderFrontend *frontend) : ReaderBackend(frontend)
	{
	file = 0;
	in = 0;

	separator.assign( (const char*) BifConst::InputRaw::record_separator->Bytes(),
			  BifConst::InputRaw::record_separator->Len());

	if ( separator.size() != 1 )
		Error("separator length has to be 1. Separator will be truncated.");
	}

Raw::~Raw()
	{
	DoClose();
	}

void Raw::DoClose()
	{
	if ( file != 0 )
		CloseInput();
	}

bool Raw::OpenInput()
	{
	if ( execute )
		{
		file = popen(fname.c_str(), "r");
		if ( file == NULL )
			{
			Error(Fmt("Could not execute command %s", fname.c_str()));
			return false;
			}
		}
	else
		{
		file = fopen(fname.c_str(), "r");
		if ( file == NULL )
			{
			Error(Fmt("Init: cannot open %s", fname.c_str()));
			return false;
			}
		}

	// This is defined in input/fdstream.h
	in = new boost::fdistream(fileno(file));

	if ( execute && Info().mode == MODE_STREAM )
		fcntl(fileno(file), F_SETFL, O_NONBLOCK);

	return true;
	}

bool Raw::CloseInput()
	{
	if ( file == NULL )
		{
		InternalError(Fmt("Trying to close closed file for stream %s", fname.c_str()));
		return false;
		}
#ifdef DEBUG
	Debug(DBG_INPUT, "Raw reader starting close");
#endif

	delete in;

	if ( execute )
		pclose(file);
	else
		fclose(file);

	in = NULL;
	file = NULL;

#ifdef DEBUG
	Debug(DBG_INPUT, "Raw reader finished close");
#endif

	return true;
	}

bool Raw::DoInit(const ReaderInfo& info, int num_fields, const Field* const* fields)
	{
	fname = info.source;
	mtime = 0;
	execute = false;
	firstrun = true;
	bool result;

	if ( ! info.source || strlen(info.source) == 0 )
		{
		Error("No source path provided");
		return false;
		}

	if ( num_fields != 1 )
		{
		Error("Filter for raw reader contains more than one field. "
		      "Filters for the raw reader may only contain exactly one string field. "
		      "Filter ignored.");
		return false;
		}

	if ( fields[0]->type != TYPE_STRING )
		{
		Error("Filter for raw reader contains a field that is not of type string.");
		return false;
		}

	// do Initialization
	string source = string(info.source);
	char last = info.source[source.length() - 1];
	if ( last == '|' )
		{
		execute = true;
		fname = source.substr(0, fname.length() - 1);

		if ( (info.mode != MODE_MANUAL) )
			{
			Error(Fmt("Unsupported read mode %d for source %s in execution mode",
				  info.mode, fname.c_str()));
			return false;
			}

		result = OpenInput();

		}
	else
		{
		execute = false;
		result = OpenInput();
		}

	if ( result == false )
		return result;

#ifdef DEBUG
	Debug(DBG_INPUT, "Raw reader created, will perform first update");
#endif

	// after initialization - do update
	DoUpdate();

#ifdef DEBUG
	Debug(DBG_INPUT, "First update went through");
#endif
	return true;
	}


bool Raw::GetLine(string& str)
	{
	if ( in->peek() == std::iostream::traits_type::eof() )
		return false;

	if ( in->eofbit == true || in->failbit == true )
		return false;

	return getline(*in, str, separator[0]);
	}

// read the entire file and send appropriate thingies back to InputMgr
bool Raw::DoUpdate()
	{
	if ( firstrun )
		firstrun = false;

	else
		{
		switch ( Info().mode  ) {
		case MODE_REREAD:
			{
			// check if the file has changed
			struct stat sb;
			if ( stat(fname.c_str(), &sb) == -1 )
				{
				Error(Fmt("Could not get stat for %s", fname.c_str()));
				return false;
				}

			if ( sb.st_mtime <= mtime )
				// no change
				return true;

			mtime = sb.st_mtime;
			// file changed. reread.
			//
			// fallthrough
			}

		case MODE_MANUAL:
		case MODE_STREAM:
			if ( Info().mode == MODE_STREAM && file != NULL && in != NULL )
				{
				//fpurge(file);
				in->clear(); // remove end of file evil bits
				break;
				}

			CloseInput();
			if ( ! OpenInput() )
				return false;

			break;

		default:
			assert(false);
		}
		}

	string line;
	while ( GetLine(line) )
		{
		assert (NumFields() == 1);

		Value** fields = new Value*[1];

		// filter has exactly one text field. convert to it.
		Value* val = new Value(TYPE_STRING, true);
		val->val.string_val.data = copy_string(line.c_str());
		val->val.string_val.length = line.size();
		fields[0] = val;

		Put(fields);
		}

#ifdef DEBUG
	Debug(DBG_INPUT, "DoUpdate finished successfully");
#endif

	return true;
	}

bool Raw::DoHeartbeat(double network_time, double current_time)
	{
	switch ( Info().mode ) {
		case MODE_MANUAL:
			// yay, we do nothing :)
			break;

		case MODE_REREAD:
		case MODE_STREAM:
#ifdef DEBUG
	Debug(DBG_INPUT, "Starting Heartbeat update");
#endif
			Update();	// call update and not DoUpdate, because update
					// checks disabled.
#ifdef DEBUG
	Debug(DBG_INPUT, "Finished with heartbeat update");
#endif
			break;
		default:
			assert(false);
	}

	return true;
	}
