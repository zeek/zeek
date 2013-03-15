// See the file "COPYING" in the main distribution directory for copyright.

#include "Raw.h"
#include "NetVar.h"

#include "../../threading/SerialTypes.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>

using namespace input::reader;
using threading::Value;
using threading::Field;

const int Raw::block_size = 512; // how big do we expect our chunks of data to be... 

Raw::Raw(ReaderFrontend *frontend) : ReaderBackend(frontend)
	{
	file = 0;
	separator.assign( (const char*) BifConst::InputRaw::record_separator->Bytes(),
			  BifConst::InputRaw::record_separator->Len());

	sep_length = BifConst::InputRaw::record_separator->Len();

	buf = 0;
	outbuf = 0;
	bufpos = 0;

	stdin_fileno = fileno(stdin);
	stdout_fileno = fileno(stdout);
	stderr_fileno = fileno(stderr);

	// and because we later assume this...
	assert(stdin_fileno == 0);
	assert(stdout_fileno == 1);
	assert(stderr_fileno == 2);
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

bool Raw::Execute() 
	{
	int stdout_pipe[2];
        pid_t pid;

	if (pipe(stdout_pipe) != 0)
		{
		Error(Fmt("Could not open pipe: %d", errno));
		return false;
		}

	pid = fork();
	if ( pid < 0 )
		{
		Error(Fmt("Could not create child process: %d", errno));
		return false;
		}
	else if ( pid == 0 ) 
		{
		// we are the child.
		close(stdout_pipe[stdin_fileno]);
		dup2(stdout_pipe[stdout_fileno], stdout_fileno);
		//execv("/usr/bin/uname",test);
		execl("/bin/sh", "sh", "-c", fname.c_str(), NULL);
		fprintf(stderr, "Exec failed :(......\n");
		exit(255);
		}
	else
		{
		// we are the parent
		close(stdout_pipe[stdout_fileno]);
		file = fdopen(stdout_pipe[stdin_fileno], "r");
		if ( file == 0 )
			{
			Error("Could not convert fileno to file");
			return false;
			}
		return true;
		}
	}

bool Raw::OpenInput()
	{
	if ( execute )
		{
		if ( ! Execute() ) 
			return false;
		}
	else
		{
		file = fopen(fname.c_str(), "r");
		if ( !file )
			{
			Error(Fmt("Init: cannot open %s", fname.c_str()));
			return false;
			}
		}

	//if ( execute && Info().mode == MODE_STREAM )
	//	fcntl(fileno(file), F_SETFL, O_NONBLOCK);

	//fcntl(fileno(file), F_SETFD, FD_CLOEXEC);
	return true;
	}

bool Raw::CloseInput()
	{
	if ( file == 0 )
		{
		InternalError(Fmt("Trying to close closed file for stream %s", fname.c_str()));
		return false;
		}
#ifdef DEBUG
	Debug(DBG_INPUT, "Raw reader starting close");
#endif

	if ( execute )
		pclose(file);
	else
		fclose(file);

	file = 0;

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

		/*
		if ( (info.mode != MODE_MANUAL) )
			{
			Error(Fmt("Unsupported read mode %d for source %s in execution mode",
				  info.mode, fname.c_str()));
			return false;
			}
			*/

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


int64_t Raw::GetLine()
	{

	errno = 0;
	uint64_t pos = 0;

	if ( buf == 0 )
		buf = new char[block_size];

	int repeats = 1;

	for (;;)
		{
		size_t readbytes = fread(buf+bufpos, 1, block_size-bufpos, file);
		pos += bufpos + readbytes;
		bufpos = 0; // read full block size in next read...

		if ( errno != 0 ) 
			break;

		char* token = strnstr(buf, separator.c_str(), block_size*repeats-pos);

		if ( token == 0 ) 
			{
			// we did not find it and have to search again in the next try. resize buffer....
			// but first check if we encountered the file end - because if we did this was it.
			if ( feof(file) != 0 ) 
				{
				outbuf = buf;
				buf = 0;
				if ( pos == 0 ) 
					return -1; // signal EOF - and that we had no more data.
				else 
					return pos;
				}
			
			repeats++;
			// bah, we cannot use realloc because we would have to change the delete in the manager to a delete :(
			//char* newbuf = realloc(buf,block_size*repeats);
			char * newbuf = new char[block_size*repeats];
			memcpy(newbuf, buf, block_size*(repeats-1));
			delete buf;
			buf = newbuf;
			}
		else
			{
			outbuf = buf;
			buf = 0;
			buf = new char[block_size];


			if ( token - outbuf < pos  ) 
				{
				// we have leftovers. copy them into the buffer for the next line
				buf = new char[block_size];
				memcpy(buf, token + sep_length, -(token - outbuf + sep_length) +pos);
				bufpos =  -(token - outbuf + sep_length) +pos;
				}
			
			pos = token-outbuf;
			return  pos;
			}

		}

	if ( errno == 0 ) {
		assert(false);
	} else if ( errno == EAGAIN || errno == EAGAIN || errno == EINTR ) {
		return -2;
	} else {
		// an error code we did no expect. This probably is bad.
		Error(Fmt("Reader encountered unexpected error code %d", errno));
		return -3;
	}

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
			if ( Info().mode == MODE_STREAM && file != 0 )
				{
				//fpurge(file);
				clearerr(file);  // remove end of file evil bits
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
	assert (NumFields() == 1);
	for ( ;; )
		{
		int64_t length = GetLine();
		if ( length == -3 ) 
			return false;
		else if ( length == -2 || length == -1 ) 
			// no data ready or eof
			break;
		
		Value** fields = new Value*[1];

		// filter has exactly one text field. convert to it.
		Value* val = new Value(TYPE_STRING, true);
		val->val.string_val.data = outbuf;
		val->val.string_val.length = length;
		fields[0] = val;

		Put(fields);

		outbuf = 0;
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
