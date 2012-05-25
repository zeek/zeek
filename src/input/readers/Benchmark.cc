// See the file "COPYING" in the main distribution directory for copyright.

#include "Benchmark.h"
#include "NetVar.h"

#include "../../threading/SerialTypes.h"

#define MANUAL 0
#define REREAD 1
#define STREAM 2

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../../threading/Manager.h"

using namespace input::reader;
using threading::Value;
using threading::Field;



Benchmark::Benchmark(ReaderFrontend *frontend) : ReaderBackend(frontend)
	{
	multiplication_factor = double(BifConst::InputBenchmark::factor);	
	autospread = double(BifConst::InputBenchmark::autospread);	
	spread = int(BifConst::InputBenchmark::spread);
	add = int(BifConst::InputBenchmark::addfactor);
	autospread_time = 0;
	stopspreadat = int(BifConst::InputBenchmark::stopspreadat);
	timedspread = double(BifConst::InputBenchmark::timedspread);
	heart_beat_interval = double(BifConst::Threading::heart_beat_interval);

	}

Benchmark::~Benchmark()
	{
	DoClose();
	}

void Benchmark::DoClose()
	{
	}

bool Benchmark::DoInit(string path, int arg_mode, int arg_num_fields, const Field* const* arg_fields)
	{
	mode = arg_mode;
	
	num_fields = arg_num_fields;
	fields = arg_fields;
	num_lines = atoi(path.c_str());
	
	if ( autospread != 0.0 )
		autospread_time = (int) ( (double) 1000000 / (autospread * (double) num_lines) );

	if ( ( mode != MANUAL ) && (mode != REREAD) && ( mode != STREAM ) ) 
		{
		Error(Fmt("Unsupported read mode %d for source %s", mode, path.c_str()));
		return false;
		}

	heartbeatstarttime = CurrTime();
	DoUpdate();

	return true;
	}

string Benchmark::RandomString(const int len) 
	{
	string s(len, ' ');

	static const char values[] =
	"0123456789!@#$%^&*()-_=+{}[]\\|"
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz";

	for (int i = 0; i < len; ++i) 
        	s[i] = values[rand() / (RAND_MAX / sizeof(values))];

	return s;
	}

double Benchmark::CurrTime() 
	{
	struct timeval tv;
	assert ( gettimeofday(&tv, 0) >= 0 );

	return double(tv.tv_sec) + double(tv.tv_usec) / 1e6;
	}


// read the entire file and send appropriate thingies back to InputMgr
bool Benchmark::DoUpdate() 
	{
        int linestosend = num_lines * heart_beat_interval;
	for ( int i = 0; i < linestosend; i++ ) 
		{
		Value** field = new Value*[num_fields];
		for  (unsigned int j = 0; j < num_fields; j++ ) 
			field[j] = EntryToVal(fields[j]->type, fields[j]->subtype);

		if ( mode == STREAM ) 
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
			while ( diff/heart_beat_interval < i/(linestosend 
			        + (linestosend * timedspread) ) );
			}

	}

	if ( mode != STREAM )  
		EndCurrentSend();

	return true;
}

threading::Value* Benchmark::EntryToVal(TypeTag type, TypeTag subtype) 
	{
	Value* val = new Value(type, true);

	// basically construct something random from the fields that we want.
	
	switch ( type ) {
	case TYPE_ENUM:
		assert(false); // no enums, please.
	case TYPE_STRING:
		val->val.string_val = new string(RandomString(10));
		break;

	case TYPE_BOOL:
		val->val.int_val = 1; // we never lie.
		break;

	case TYPE_INT:
		val->val.int_val = rand();
		break;

	case TYPE_TIME:
		val->val.double_val = CurrTime();
		break;

	case TYPE_DOUBLE:
	case TYPE_INTERVAL:
		val->val.double_val = random();
		break;

	case TYPE_COUNT:
	case TYPE_COUNTER:
		val->val.uint_val = rand();
		break;

	case TYPE_PORT:
		val->val.port_val.port = rand() / (RAND_MAX / 60000);
		val->val.port_val.proto = TRANSPORT_UNKNOWN;
		break;

	case TYPE_SUBNET: 
		{
		val->val.subnet_val.prefix = StringToAddr("192.168.17.1");
		val->val.subnet_val.length = 16;
		}
		break;

	case TYPE_ADDR: 
		val->val.addr_val = StringToAddr("192.168.17.1");
		break;

	case TYPE_TABLE:
	case TYPE_VECTOR:
		// First - common initialization
		// Then - initialization for table.
		// Then - initialization for vector.
		// Then - common stuff
		{
		// how many entries do we have...
		unsigned int length = rand() / (RAND_MAX / 15);

		Value** lvals = new Value* [length];

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
			Value* newval = EntryToVal(subtype, TYPE_ENUM);
			if ( newval == 0 ) 
				{
				Error("Error while reading set");
				return 0;
				}
			lvals[pos] = newval;
			}

		break;
		}


	default:
		Error(Fmt("unsupported field format %d", type));
		return 0;
	}	

	return val;

	}


bool Benchmark::DoHeartbeat(double network_time, double current_time)
{
	ReaderBackend::DoHeartbeat(network_time, current_time);
	num_lines = (int) ( (double) num_lines*multiplication_factor);
	num_lines += add;
	heartbeatstarttime = CurrTime();

	switch ( mode ) {
		case MANUAL:
			// yay, we do nothing :)
			break;
		case REREAD:
		case STREAM:
			if ( multiplication_factor != 1 || add != 0 ) 
				{
				// we have to document at what time we changed the factor to what value.
				Value** v = new Value*[2];
				v[0] = new Value(TYPE_COUNT, true);
				v[0]->val.uint_val = num_lines;
				v[1] = new Value(TYPE_TIME, true);
				v[1]->val.double_val = CurrTime();

				SendEvent("lines_changed", 2, v);
				}

			if ( autospread != 0.0 ) 
				// because executing this in every loop is apparently too expensive.
				autospread_time = (int) ( (double) 1000000 / (autospread * (double) num_lines) );
	
			Update(); // call update and not DoUpdate, because update actually checks disabled.

			SendEvent("HeartbeatDone", 0, 0);
			break;
		default:
			assert(false);
	}

	return true;
}

