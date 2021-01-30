// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/input/readers/benchmark/Benchmark.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#include "zeek/threading/SerialTypes.h"
#include "zeek/threading/Manager.h"

#include "input/readers/benchmark/benchmark.bif.h"

using zeek::threading::Value;
using zeek::threading::Field;

namespace zeek::input::reader::detail {

Benchmark::Benchmark(ReaderFrontend *frontend) : ReaderBackend(frontend)
	{
	num_lines = 0;
	multiplication_factor = double(BifConst::InputBenchmark::factor);
	autospread = double(BifConst::InputBenchmark::autospread);
	spread = int(BifConst::InputBenchmark::spread);
	add = int(BifConst::InputBenchmark::addfactor);
	autospread_time = 0;
	stopspreadat = int(BifConst::InputBenchmark::stopspreadat);
	timedspread = double(BifConst::InputBenchmark::timedspread);
	heartbeatstarttime = 0;
	heartbeat_interval = double(BifConst::Threading::heartbeat_interval);

	ascii = new threading::formatter::Ascii(this, threading::formatter::Ascii::SeparatorInfo());
	}

Benchmark::~Benchmark()
	{
	DoClose();

	delete ascii;
	}

void Benchmark::DoClose()
	{
	}

bool Benchmark::DoInit(const ReaderInfo& info, int num_fields, const threading::Field* const* fields)
	{
	num_lines = atoi(info.source);

	if ( autospread != 0.0 )
		autospread_time = (int) ( (double) 1000000 / (autospread * (double) num_lines) );

	heartbeatstarttime = CurrTime();
	DoUpdate();

	return true;
	}

std::string Benchmark::RandomString(const int len)
	{
	std::string s(len, ' ');

	static const char values[] =
	"0123456789!@#$%^&*()-_=+{}[]\\|"
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz";

	for (int i = 0; i < len; ++i)
		s[i] = values[random() / (RAND_MAX / sizeof(values))];

	return s;
	}

double Benchmark::CurrTime()
	{
	struct timeval tv;
	if ( gettimeofday(&tv, 0) != 0 ) {
		FatalError(Fmt("Could not get time: %d", errno));
	}

	return double(tv.tv_sec) + double(tv.tv_usec) / 1e6;
	}


// read the entire file and send appropriate thingies back to InputMgr
bool Benchmark::DoUpdate()
	{
	int linestosend = num_lines * heartbeat_interval;
	for ( int i = 0; i < linestosend; i++ )
		{
		threading::Value** field = new threading::Value*[NumFields()];
		for  (int j = 0; j < NumFields(); j++ )
			field[j] = EntryToVal(Fields()[j]->type, Fields()[j]->subtype);

		if ( Info().mode  == MODE_STREAM )
			// do not do tracking, spread out elements over the second that we have...
			Put(field);
		else
			SendEntry(field);

		if ( stopspreadat == 0 || num_lines < stopspreadat )
			{
			if ( spread != 0 )
				usleep(spread);

			if ( autospread_time != 0 )
				usleep( autospread_time );
			}

		if ( timedspread != 0.0 )
			{
			double diff;
			do
				diff = CurrTime() - heartbeatstarttime;
			while ( diff/heartbeat_interval < i/(linestosend
			        + (linestosend * timedspread) ) );
			}

	}

	if ( Info().mode != MODE_STREAM )
		EndCurrentSend();

	return true;
}

threading::Value* Benchmark::EntryToVal(TypeTag type, TypeTag subtype)
	{
	auto* val = new threading::Value(type, subtype, true);

	// basically construct something random from the fields that we want.

	switch ( type ) {
	case TYPE_ENUM:
		assert(false); // no enums, please.

	case TYPE_STRING:
		{
		std::string rnd = RandomString(10);
		val->val.string_val.data = util::copy_string(rnd.c_str());
		val->val.string_val.length = rnd.size();
		break;
		}

	case TYPE_BOOL:
		val->val.int_val = 1; // we never lie.
		break;

	case TYPE_INT:
		val->val.int_val = random();
		break;

	case TYPE_TIME:
		val->val.double_val = CurrTime();
		break;

	case TYPE_DOUBLE:
	case TYPE_INTERVAL:
		val->val.double_val = random();
		break;

	case TYPE_COUNT:
		val->val.uint_val = random();
		break;

	case TYPE_PORT:
		val->val.port_val.port = random() / (RAND_MAX / 60000);
		val->val.port_val.proto = TRANSPORT_UNKNOWN;
		break;

	case TYPE_SUBNET:
		{
		val->val.subnet_val.prefix = ascii->ParseAddr("192.168.17.1");
		val->val.subnet_val.length = 16;
		}
		break;

	case TYPE_ADDR:
		val->val.addr_val = ascii->ParseAddr("192.168.17.1");
		break;

	case TYPE_TABLE:
	case TYPE_VECTOR:
		// First - common initialization
		// Then - initialization for table.
		// Then - initialization for vector.
		// Then - common stuff
		{
		// how many entries do we have...
		unsigned int length = random() / (RAND_MAX / 15);

		threading::Value** lvals = new threading::Value* [length];

		if ( type == TYPE_TABLE )
			{
			val->val.set_val.vals = lvals;
			val->val.set_val.size = length;
			}
		else if ( type == TYPE_VECTOR )
			{
			val->val.vector_val.vals = lvals;
			val->val.vector_val.size = length;
			}
		else
			assert(false);

		if ( length == 0 )
			break; //empty

		for ( unsigned int pos = 0; pos < length; pos++ )
			{
			threading::Value* newval = EntryToVal(subtype, TYPE_ENUM);
			if ( newval == nullptr )
				{
				Error("Error while reading set");
				delete val;
				return nullptr;
				}
			lvals[pos] = newval;
			}

		break;
		}


	default:
		Error(Fmt("unsupported field format %d", type));
		delete val;
		return nullptr;
	}

	return val;

	}


bool Benchmark::DoHeartbeat(double network_time, double current_time)
{
	num_lines = (int) ( (double) num_lines*multiplication_factor);
	num_lines += add;
	heartbeatstarttime = CurrTime();

	switch ( Info().mode ) {
		case MODE_MANUAL:
			// yay, we do nothing :)
			break;

		case MODE_REREAD:
		case MODE_STREAM:
			if ( multiplication_factor != 1 || add != 0 )
				{
				// we have to document at what time we changed the factor to what value.
				threading::Value** v = new threading::Value*[2];
				v[0] = new threading::Value(TYPE_COUNT, true);
				v[0]->val.uint_val = num_lines;
				v[1] = new threading::Value(TYPE_TIME, true);
				v[1]->val.double_val = CurrTime();

				SendEvent("lines_changed", 2, v);
				}

			if ( autospread != 0.0 )
				// because executing this in every loop is apparently too expensive.
				autospread_time = (int) ( (double) 1000000 / (autospread * (double) num_lines) );

			Update(); // call update and not DoUpdate, because update actually checks disabled.

			SendEvent("HeartbeatDone", 0, nullptr);
			break;

		default:
			assert(false);
	}

	return true;
}

} // namespace zeek::input::reader::detail
