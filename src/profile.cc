
#include <stdio.h>
#include <memory.h>

#include "config.h"

#include "profile.h"
#include "Reporter.h"

#ifdef USE_PAPI
#include <papi.h>
#define PAPI_TOT_CYCLES    0
#define PAPI_CYCLE_FMT "llu"
#else
typedef uint64_t long_long;
#define PAPI_CYCLE_FMT PRIu64
#endif

#define PAPI_NUM_EVENTS    2

extern int time_bro;

struct ProfileItem {
	double time;
	long_long cycles;
	unsigned int mem_total;
	unsigned int mem_malloced;

	double _time_start;
	long_long _cycles_start;
	unsigned int _mem_total_start;
	unsigned int _mem_malloced_start;
	bool _started;

	int level;

	ProfileItem()
		{
		_time_start = time = 0;
		_cycles_start = cycles = 0;
		_mem_total_start = mem_total = 0;
		_mem_malloced_start = mem_malloced = 0;
        _started = false;
		level = 0;
		}
};

struct ProfileState {
	ProfileItem items[PROFILE_COUNT];
};

static ProfileState profile_state;

#ifdef USE_PAPI

static int PAPISet = PAPI_NULL;
static int have_papi = -1;

// PAPI helpers.
static void papi_init()
	{
	have_papi = 0;

	if ( PAPI_library_init(PAPI_VER_CURRENT) != PAPI_VER_CURRENT)
		{
		fprintf(stderr, "warning: cannot init PAPI library (not running as root?)!\n");
		return;
		}

	int ret;
	if ( (ret = PAPI_create_eventset(&PAPISet)) != PAPI_OK )
		{
		fprintf(stderr, "Error in creating the event set: %s\n", PAPI_strerror(ret));
		return;
		}

	if ( (ret = PAPI_add_event(PAPISet, PAPI_TOT_INS)) != PAPI_OK )
		{
		fprintf(stderr, "Error in adding into the event set (tot_ins): %s\n", PAPI_strerror(ret));
		return;
		}

	if ( (ret = PAPI_add_event(PAPISet, PAPI_TOT_CYC)) != PAPI_OK )
		{
		fprintf(stderr, "Error in adding into the event set (tot_cyc): %s\n", PAPI_strerror(ret));
		return;
		}

	PAPI_option_t options;
	memset(&options, 0, sizeof(options));
	options.domain.eventset = PAPISet;
	options.domain.domain = PAPI_DOM_ALL;
	if ( (ret = PAPI_set_opt(PAPI_DOMAIN, &options)) != PAPI_OK )
		{
		fprintf(stderr, "Error in setting PAPI domain: %s\n", PAPI_strerror(ret));
		return;
		}

	if ( (ret = PAPI_start(PAPISet)) != PAPI_OK)
		{
		fprintf(stderr, "Error in starting PAPI counters: %s\n", PAPI_strerror(ret));
		return;
		}

	have_papi = 1;
	}

#if 0
static void papi_finish()
	{
	int ret;
	long_long dummy[PAPI_NUM_EVENTS];
	if ( (ret = PAPI_stop(PAPISet, dummy)) != PAPI_OK)
		fprintf(stderr, "Error in stoppping PAPI counters: %s\n", PAPI_strerror(ret));
	}
#endif

#endif

static void print_profile_item(const char* tag, ProfileType type, ProfileType minus_type1 = PROFILE_NONE, ProfileType minus_type2 = PROFILE_NONE)
	{
	ProfileItem* i = &profile_state.items[type];

	if ( i->level > 0 )
		reporter->InternalError("level for profiler %d is not zero (but %u)\n", type, i->level);

	double time = i->time;
	unsigned int mem_total = i->mem_total;
	unsigned int mem_malloced = i->mem_malloced;
	long_long cycles = i->cycles;

	if ( minus_type1 != PROFILE_NONE )
		{
		ProfileItem* j = &profile_state.items[minus_type1];
		time -= j->time;
		mem_total -= j->mem_total;
		mem_malloced -= j->mem_malloced;
		cycles -= j->cycles;
		}

	if ( minus_type2 != PROFILE_NONE )
		{
		ProfileItem* j = &profile_state.items[minus_type2];
		time -= j->time;
		mem_total -= j->mem_total;
		mem_malloced -= j->mem_malloced;
		cycles -= j->cycles;
		}

	fprintf(stderr, "# %s %.6f/%" PAPI_CYCLE_FMT " %uM/%uM\n",
		tag, time, cycles,
		mem_total / 1024 / 1024,
		mem_malloced / 1024 / 1024);
	}

void profile_print()
	{
	if ( ! time_bro )
		return;

	print_profile_item("core-init", PROFILE_CORE_INIT);
	print_profile_item("bro_init", PROFILE_SCRIPT_INIT);
	print_profile_item("total-processing", PROFILE_PROCESSING);
	print_profile_item("total-bro", PROFILE_TOTAL);
	print_profile_item("net-run", PROFILE_NET);
	print_profile_item("cleanup", PROFILE_CLEANUP);
	print_profile_item("script-land", PROFILE_SCRIPT_LAND);
	print_profile_item("script-legacy-land", PROFILE_SCRIPT_LEGACY_LAND);
	print_profile_item("protocol-land", PROFILE_PROTOCOL_LAND);
	print_profile_item("core-other-land", PROFILE_NET, PROFILE_PROTOCOL_LAND, PROFILE_SCRIPT_LAND);
	print_profile_item("jit-land", PROFILE_JIT_LAND);
	print_profile_item("hilti-land", PROFILE_HILTI_LAND);
	print_profile_item("hilti-land-compiled-stubs", PROFILE_HILTI_LAND_COMPILED_STUBS);
	print_profile_item("hilti-land-compiled-code",  PROFILE_HILTI_LAND_COMPILED_CODE);
	}

extern "C" {
void profile_start(int64_t t)
    {
    profile_update((ProfileType)t, PROFILE_START);
    }

void profile_stop(int64_t t)
    {
    profile_update((ProfileType)t, PROFILE_STOP);
    }
}

void profile_update(ProfileType t, ProfileAction action)
	{
	if ( ! time_bro )
		return;

    switch ( t ) {
		case PROFILE_CORE_INIT:
		case PROFILE_SCRIPT_INIT:
		case PROFILE_NET:
		case PROFILE_PROCESSING:
		case PROFILE_TOTAL:
        	break;

		case PROFILE_SCRIPT_LAND:
		case PROFILE_PROTOCOL_LAND:
		case PROFILE_HILTI_LAND_COMPILED_STUBS:
		case PROFILE_HILTI_LAND_COMPILED_CODE:
        	if ( time_bro < 2 )
            	return;

        	break;

     default:
        break;
    }

	ProfileItem* i = &profile_state.items[t];

	if ( action == PROFILE_START )
		{
		if ( i->level++ > 0 )
			return;
		}

	if ( action == PROFILE_STOP )
		{
		if ( --i->level > 0 )
			return;
		}

	if ( i->level > 1 )
		return;

    if ( i->level < 0 )
        reporter->InternalError("underflow in profile_update() for type %d", t);

	unsigned int mem_total = 0;
	unsigned int mem_malloced = 0;
    // get_memory_usage(&mem_total, &mem_malloced);

	long_long cycles[PAPI_NUM_EVENTS];
#ifdef USE_PAPI
	if ( have_papi < 0 )
		papi_init();

	int ret;
	if ( have_papi && (ret = PAPI_read(PAPISet, cycles)) != PAPI_OK )
		reporter->FatalError("Error in reading PAPI counters: %s\n", PAPI_strerror(ret));
#endif

	if ( action == PROFILE_START )
		{
		i->_time_start = current_time(true);
		i->_cycles_start = cycles[0];
		i->_mem_total_start = mem_total;
		i->_mem_malloced_start = mem_malloced;
        i->_started = true;
		}

	else
		{
        if ( ! i->_started )
                reporter->InternalError("mismatching stop in profile_update() for type %d", t);

		double time_end = current_time(true);
		unsigned int mem_total_end = mem_total;
		unsigned int mem_malloced_end = mem_malloced;
		long_long cycles_end = cycles[0];

		i->time += (time_end - i->_time_start);
		i->cycles += (cycles_end - i->_cycles_start);
		i->mem_total += (mem_total_end - i->_mem_total_start);
		i->mem_malloced += (mem_malloced_end - i->_mem_malloced_start);

        i->_started = false;
		}
	}

int profile_level(ProfileType t)
{
	ProfileItem* i = &profile_state.items[t];
    return i->level;
}

