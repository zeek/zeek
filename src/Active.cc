// $Id: Active.cc 1282 2005-09-07 17:02:02Z vern $

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <arpa/inet.h>

#include <map>

#include "Active.h"
#include "util.h"
#include "Dict.h"

declare(PDict,string);
typedef PDict(string) MachineMap;
declare(PDict,MachineMap);
typedef PDict(MachineMap) ActiveMap;
declare(PDict,NumericData);
typedef PDict(NumericData) ActiveMapNumeric;

static ActiveMap active_map;
static ActiveMapNumeric active_map_numeric;

static MachineMap default_values;
static NumericData default_values_numeric;

static bool map_was_loaded = false;

bool get_map_result(uint32 ip_addr, const char* key, string& result)
	{
	const MachineMap* machine_map;
#ifndef ACTIVE_MAPPING
	machine_map = &default_values;
#else
	HashKey machinekey(ip_addr);
	machine_map = active_map.Lookup(&machinekey);

	if ( ! machine_map )
		machine_map = &default_values;
#endif
	HashKey mapkey(key);
	string* entry = machine_map->Lookup(&mapkey);
	if ( ! entry )
		{
		entry = default_values.Lookup(&mapkey);
		}

	if ( ! entry )
		{
		internal_error("Unknown active mapping entry requested: %s", key);
		return false;
		}

	result = *entry;

	return true;
	}

bool get_map_result(uint32 ip_addr, const NumericData*& result)
	{
#ifndef ACTIVE_MAPPING
	result = &default_values_numeric;
	return true;
#endif
	HashKey machinekey(&ip_addr, 1);
	NumericData* entry = active_map_numeric.Lookup(&machinekey);

	if ( ! entry )
		result = &default_values_numeric;
	else
		result = entry;

	return true;
	}


char* chop (char* s)
	{
	s[strlen(s) - 1] = 0;
	return s;
	}

map < const char *, ReassemblyPolicy, ltstr > reassem_names;

// Remember to index the table with IP address in network order!
bool load_mapping_table(const char* map_file)
	{
	reassem_names["BSD"] = RP_BSD;
	reassem_names["linux"] = RP_LINUX;
	reassem_names["last"] = RP_LAST;
	reassem_names["first"] = RP_FIRST;

	// Default values are read in from AM file under IP address 0.0.0.0
	default_values.Insert(new HashKey("accepts_rst_outside_window"),
			      new string("no"));
	default_values.Insert(new HashKey("accepts_rst_in_window"),
			      new string("yes"));
	default_values.Insert(new HashKey("accepts_rst_in_sequence"),
			      new string("yes"));
	default_values.Insert(new HashKey("mtu"),
			      new string("0"));

	default_values_numeric.path_MTU = 0;   // 0 = unknown
	default_values_numeric.hops = 0;       // 0 = unknown;
	default_values_numeric.ip_reassem = RP_UNKNOWN;
	default_values_numeric.tcp_reassem = RP_UNKNOWN;
	default_values_numeric.accepts_rst_in_window = true;
	default_values_numeric.accepts_rst_outside_window = false;


	if ( map_file && strlen(map_file) )
		{
		FILE* f = fopen(map_file, "r");
		if ( ! f )
			return false;

		char buf[512];
		if ( ! fgets(buf, sizeof(buf), f) )
			error("Error reading mapping file.\n");

		int num_fields = atoi(buf);

		string* field_names = new string[num_fields];
		for ( int i = 0; i < num_fields; ++i )
			{
			if ( ! fgets(buf, sizeof(buf), f) )
				error("Error reading mapping file.\n");
			field_names[i] = chop(buf);
			}

		if ( ! fgets(buf, sizeof(buf), f) )
			error("Error reading mapping file.\n");

		int num_machines = atoi(buf);

		for ( int j = 0; j < num_machines; ++j )
			{ // read ip address, parse it
			if ( ! fgets(buf, sizeof(buf), f) )
				error("Error reading mapping file.\n");

			uint32 ip;
			in_addr in;
			if ( ! inet_aton(chop(buf), &in) )
				error("Error reading mapping file.\n");

			ip = in.s_addr;

			MachineMap* newmap;
			NumericData* newnumeric;

			if ( ip ) // ip = 0.0.0.0 = default values
				{
				newmap = new MachineMap;
				newnumeric = new NumericData;
				}
			else
				{
				newmap = &default_values;
				newnumeric = &default_values_numeric;
				}

			for ( int i = 0; i < num_fields; ++i )
				{
				if ( ! fgets(buf, sizeof(buf), f) )
					error("Error reading mapping file.\n");

				string fname = field_names[i];

				chop(buf);

				// Don't try to parse an unknown value ("").
				if ( streq(buf, "") )
					continue;

				HashKey mapkey(fname.c_str());
				newmap->Insert(&mapkey, new string(buf));

				if ( fname == "mtu" )
					newnumeric->path_MTU = atoi(buf);

				else if ( fname == "hops" )
					newnumeric->hops = atoi(buf);

				else if ( fname == "tcp_segment_overlap" )
					newnumeric->tcp_reassem = reassem_names[buf];

				else if ( fname == "overlap_policy" )
					newnumeric->ip_reassem = reassem_names[buf];

				else if ( fname == "accepts_rst_in_window" )
					newnumeric->accepts_rst_in_window = streq(buf, "yes");

				else if ( fname == "accepts_rst_outside_window" )
					newnumeric->accepts_rst_outside_window = streq(buf, "yes");

				else if ( fname == "accepts_rst_in_sequence" )
					newnumeric->accepts_rst_in_sequence = streq(buf, "yes");

				else
					warn("unrecognized mapping file tag:", fname.c_str());
				}

			HashKey machinekey(&ip, 1);
			active_map.Insert(&machinekey, newmap);
			active_map_numeric.Insert(&machinekey, newnumeric);
			}

		delete [] field_names;
		}

	map_was_loaded = true;

	return true;
	}
