
#include <stdio.h>
#include <memory.h>

#include "config.h"

#include "profile.h"
#include "Reporter.h"

#ifdef USE_PAPI
#include <papi.h>
#define  PAPI_NUM_EVENTS    2
#define  PAPI_TOT_CYCLES    0
#else
typedef long_long uint64_t;
#endif

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

	unsigned int level;

	ProfileItem()
		{
		_time_start = time = 0;
		_cycles_start = cycles = 0;
		_mem_total_start = mem_total = 0;
		_mem_malloced_start = mem_malloced = 0;
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

static void print_profile_item(const char* tag, ProfileType type)
	{
	ProfileItem* i = &profile_state.items[type];

	if ( i->level > 0 )
		reporter->InternalError("level for profiler %d is not zero (but %u)\n", type, i->level);

	fprintf(stderr, "# %s %.6f/%llu %uM/%uM\n",
		tag, i->time, i->cycles,
		i->mem_total / 1024 / 1024,
		i->mem_malloced / 1024 / 1024);
	}

void profile_print()
	{
	if ( ! time_bro )
		return;

	print_profile_item("core-init", PROFILE_CORE_INIT);
	print_profile_item("bro_init", PROFILE_SCRIPT_INIT);
	print_profile_item("net-processing", PROFILE_NET);
	print_profile_item("total-processing", PROFILE_PROCESSING);
	print_profile_item("total-script", PROFILE_SCRIPT_LAND);
	print_profile_item("total-protocols", PROFILE_PROTOCOL_LAND);
	print_profile_item("total-bro", PROFILE_TOTAL);
	}

void profile_update(ProfileType t, ProfileAction action)
	{
	if ( ! time_bro )
		return;

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

	unsigned int mem_total;
	unsigned int mem_malloced;
	get_memory_usage(&mem_total, &mem_malloced);

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
		}

	else
		{
		double time_end = current_time(true);
		unsigned int mem_total_end = mem_total;
		unsigned int mem_malloced_end = mem_malloced;
		long_long cycles_end = cycles[0];

		i->time += (time_end - i->_time_start);
		i->cycles += (cycles_end - i->_cycles_start);
		i->mem_total += (mem_total_end - i->_mem_total_start);
		i->mem_malloced += (mem_malloced_end - i->_mem_malloced_start);
		}
	}

