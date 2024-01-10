// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/Val.h"

namespace zeek {

#ifdef USE_GEOIP

#include <maxminddb.h>

class MMDB {
public:
    MMDB(const char* filename, struct stat info);

    ~MMDB();

    bool Lookup(const zeek::IPAddr& addr, MMDB_lookup_result_s& result);
    bool StaleDB();
    const char* Filename();

private:
    MMDB_lookup_result_s Lookup(const struct sockaddr* const sa);

    MMDB_s mmdb;
    struct stat file_info;
    bool lookup_error;
    double last_check;
};

#endif // USE_GEOIP

ValPtr mmdb_open_location_db(zeek::StringVal* filename);
ValPtr mmdb_open_asn_db(zeek::StringVal* filename);

RecordValPtr mmdb_lookup_location(zeek::AddrVal* addr);
RecordValPtr mmdb_lookup_autonomous_system(zeek::AddrVal* addr);

} // namespace zeek
