#pragma once

#include <netdb.h>
#include <sys/socket.h>
#include <cstdint>
#include <string>

#include "zeek/IPAddr.h"
#include "zeek/Val.h"

namespace zeek::detail
	{

class DNS_Mapping;
using DNS_MappingPtr = std::shared_ptr<DNS_Mapping>;

class DNS_Mapping
	{
public:
	DNS_Mapping() = delete;
	DNS_Mapping(std::string host, struct hostent* h, uint32_t ttl, int type);
	DNS_Mapping(const IPAddr& addr, struct hostent* h, uint32_t ttl);
	DNS_Mapping(FILE* f);

	bool NoMapping() const { return no_mapping; }
	bool InitFailed() const { return init_failed; }

	~DNS_Mapping() = default;

	// Returns nil if this was an address request.
	// TODO: fix this an uses of this to just return the empty string
	const char* ReqHost() const { return req_host.empty() ? nullptr : req_host.c_str(); }
	const IPAddr& ReqAddr() const { return req_addr; }
	std::string ReqStr() const { return req_host.empty() ? req_addr.AsString() : req_host; }
	int ReqType() const { return req_type; }

	ListValPtr Addrs();
	TableValPtr AddrsSet(); // addresses returned as a set
	StringValPtr Host();

	double CreationTime() const { return creation_time; }
	uint32_t TTL() const { return req_ttl; }

	void Save(FILE* f) const;

	bool Failed() const { return failed; }
	bool Valid() const { return ! failed; }

	bool Expired() const { return util::current_time() > (creation_time + req_ttl); }

	void Merge(const DNS_MappingPtr& other);

	static void InitializeCache(FILE* f);
	static bool ValidateCacheVersion(FILE* f);

protected:
	friend class DNS_Mgr;

	void Init(struct hostent* h);
	void Clear();

	std::string req_host;
	IPAddr req_addr;
	uint32_t req_ttl = 0;
	int req_type = 0;

	// This class supports multiple names per address, but we only store one of them.
	std::vector<std::string> names;
	StringValPtr host_val;

	std::vector<IPAddr> addrs;
	ListValPtr addrs_val;

	double creation_time = 0.0;
	bool no_mapping = false; // when initializing from a file, immediately hit EOF
	bool init_failed = false;
	bool failed = false;
	};

	} // namespace zeek::detail
