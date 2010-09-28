// $Id: Active.h 80 2004-07-14 20:15:50Z jason $

#ifndef active_h
#define active_h

#include <string>
using namespace std;

#include "util.h"

enum ReassemblyPolicy {
	RP_UNKNOWN,
	RP_BSD,	// Left-trim to equal or lower offset frags
	RP_LINUX,	// Left-trim to strictly lower offset frags
	RP_FIRST,	// Accept only new (no previous value) octets
	RP_LAST	// Accept all
};

struct NumericData {
	ReassemblyPolicy ip_reassem;
	ReassemblyPolicy tcp_reassem;
	unsigned short path_MTU;	// 0 = unknown
	unsigned char hops;	// 0 = unknown
	bool accepts_rst_in_window;
	bool accepts_rst_outside_window;
	bool accepts_rst_in_sequence;
};

// Return value is whether or not there was a known result for that
// machine (actually, IP address in network order); if not, a default
// is returned. Note that the map data is a string in all cases: the
// numeric form is more efficient and is to be preferred ordinarily.
bool get_map_result(uint32 ip_addr, const char* key, string& result);

// Basically a special case of get_map_result(), but returns numbers
// directly for efficiency reasons, since these are frequently
// looked up. ### Perhaps a better generic mechanism is in order.
bool get_map_result(uint32 ip_addr, const NumericData*& result);

// Reads in AM data from the specified file (basically [IP, policy] tuples)
// Should be called at initialization time.
bool load_mapping_table(const char* map_file);

#endif
