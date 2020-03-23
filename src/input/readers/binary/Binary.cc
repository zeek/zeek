// See the file "COPYING" in the main distribution directory for copyright.

#include <sys/stat.h>

#include "Binary.h"
#include "binary.bif.h"

#include "threading/SerialTypes.h"

using namespace input::reader;
using threading::Value;
using threading::Field;

streamsize Binary::chunk_size = 0;

Binary::Binary(ReaderFrontend *frontend)
	: ReaderBackend(frontend), in(0), mtime(0), ino(0), firstrun(true)
	{
	if ( ! chunk_size )
		{
		chunk_size = BifConst::InputBinary::chunk_size;

		if ( ! chunk_size )
			chunk_size = 1024;
		}
	}

Binary::~Binary()
	{
	DoClose();
	}

void Binary::DoClose()
	{
	if ( in )
		CloseInput();
	}

bool Binary::OpenInput()
	{
	in = new ifstream(fname.c_str(), ios_base::in | ios_base::binary);

	if ( in->fail() )
		{
		Error(Fmt("Init: cannot open %s", fname.c_str()));
		return false;
		}

	return true;
	}

bool Binary::CloseInput()
	{
	if ( ! in || ! in->is_open() )
		{
		InternalWarning(Fmt("Trying to close closed file for stream %s",
		                    fname.c_str()));
		return false;
		}

#ifdef DEBUG
	Debug(DBG_INPUT, "Binary reader starting close");
#endif

	in->close();
	delete in;
	in = 0;

#ifdef DEBUG
	Debug(DBG_INPUT, "Binary reader finished close");
#endif

	return true;
	}

bool Binary::DoInit(const ReaderInfo& info, int num_fields,
                    const Field* const* fields)
	{
	in = 0;
	mtime = 0;
	ino = 0;
	firstrun = true;

	path_prefix.assign((const char*) BifConst::InputBinary::path_prefix->Bytes(),
	                   BifConst::InputBinary::path_prefix->Len());

	if ( ! info.source || strlen(info.source) == 0 )
		{
		Error("No source path provided");
		return false;
		}

	if ( num_fields != 1 )
		{
		Error("Filter for binary reader contains more than one field. Filters "
		      "for binary reader must contain exactly one string field. "
		      "Filter ignored.");
		return false;
		}

	if ( fields[0]->type != TYPE_STRING )
		{
		Error("Filter for binary reader contains a non-string field.");
		return false;
		}

	// do initialization
	fname = info.source;

	// Handle path-prefixing. See similar logic in Ascii::OpenFile().
	if ( fname.front() != '/' && ! path_prefix.empty() )
		{
		string path = path_prefix;
		std::size_t last = path.find_last_not_of('/');

		if ( last == string::npos ) // Nothing but slashes -- weird but ok...
			path = "/";
		else
			path.erase(last + 1);

		fname = path + "/" + fname;
		}

	if ( ! OpenInput() )
		return false;

	if ( UpdateModificationTime() == -1 )
		return false;

#ifdef DEBUG
	Debug(DBG_INPUT, "Binary reader created, will perform first update");
#endif

	// after initialization - do update
	DoUpdate();

#ifdef DEBUG
	Debug(DBG_INPUT, "Binary reader did first update");
#endif

	return true;
	}

streamsize Binary::GetChunk(char** chunk)
	{
	if ( in->peek() == std::iostream::traits_type::eof() )
		return 0;

	if ( in->eof() == true || in->fail() == true )
		return 0;

	*chunk = new char[chunk_size];

	in->read(*chunk, chunk_size);

	streamsize bytes_read = in->gcount();

	if ( ! bytes_read )
		{
		delete [] *chunk;
		*chunk = 0;
		return 0;
		}

	// probably faster to just not resize if bytes_read < chunk_size, since
	// length of valid data is known

	return bytes_read;
	}

int Binary::UpdateModificationTime()
	{
	struct stat sb;

	if ( stat(fname.c_str(), &sb) == -1 )
		{
		Error(Fmt("Could not get stat for %s", fname.c_str()));
		return -1;
		}

	if ( sb.st_ino == ino && sb.st_mtime == mtime )
		// no change
		return 0;

	mtime = sb.st_mtime;
	ino = sb.st_ino;
	return 1;
	}

// read the entire file and send appropriate thingies back to InputMgr
bool Binary::DoUpdate()
	{
	if ( firstrun )
		firstrun = false;

	else
		{
		switch ( Info().mode  ) {
		case MODE_REREAD:
			{
			switch ( UpdateModificationTime() ) {
			case -1:
				return false; // error
			case 0:
				return true; // no change
			case 1:
				break; // file changed. reread.
			default:
				assert(false);
			}
			// fallthrough
			}

		case MODE_MANUAL:
		case MODE_STREAM:
			if ( Info().mode == MODE_STREAM && in )
				{
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

	char* chunk = 0;
	streamsize size = 0;
	while ( (size = GetChunk(&chunk)) )
		{
		assert (NumFields() == 1);

		Value** fields = new Value*[1];

		// filter has exactly one text field. convert to it.
		Value* val = new Value(TYPE_STRING, true);
		val->val.string_val.data = chunk;
		val->val.string_val.length = size;
		fields[0] = val;

		if ( Info().mode == MODE_STREAM )
			Put(fields);
		else
			SendEntry(fields);
		}

	if ( Info().mode != MODE_STREAM )
		EndCurrentSend();

#ifdef DEBUG
	Debug(DBG_INPUT, "DoUpdate finished successfully");
#endif

	return true;
	}

bool Binary::DoHeartbeat(double network_time, double current_time)
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
