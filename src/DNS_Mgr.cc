// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"

#include "DNS_Mgr.h"

#include <sys/types.h>
#include <sys/socket.h>
#ifdef TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <netinet/in.h>

#include <errno.h>
#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif
#include <stdlib.h>

#include <algorithm>

#include "Event.h"
#include "Net.h"
#include "Val.h"
#include "Var.h"
#include "Reporter.h"
#include "iosource/Manager.h"
#include "digest.h"

extern "C" {
extern int select(int, fd_set *, fd_set *, fd_set *, struct timeval *);

#include <netdb.h>

#include "nb_dns.h"
}


class DNS_Mgr_Request {
public:
	DNS_Mgr_Request(const char* h, int af, bool is_txt)
	    : host(copy_string(h)), fam(af), qtype(is_txt ? 16 : 0), addr(),
	      request_pending()
		{ }

	DNS_Mgr_Request(const IPAddr& a)
	    : host(), fam(), qtype(), addr(a), request_pending()
		{ }

	~DNS_Mgr_Request()			{ delete [] host; }

	// Returns nil if this was an address request.
	const char* ReqHost() const	{ return host; }
	const IPAddr& ReqAddr() const		{ return addr; }
	bool ReqIsTxt() const	{ return qtype == 16; }

	int MakeRequest(nb_dns_info* nb_dns);
	int RequestPending() const	{ return request_pending; }
	void RequestDone()	{ request_pending = 0; }


protected:
	char* host;	// if non-nil, this is a host request
	int fam;	// address family query type for host requests
	int qtype;	// Query type
	IPAddr addr;
	int request_pending;
};

int DNS_Mgr_Request::MakeRequest(nb_dns_info* nb_dns)
	{
	if ( ! nb_dns )
		return 0;

	request_pending = 1;

	char err[NB_DNS_ERRSIZE];
	if ( host )
		return nb_dns_host_request2(nb_dns, host, fam, qtype, (void*) this, err) >= 0;
	else
		{
		const uint32_t* bytes;
		int len = addr.GetBytes(&bytes);
		return nb_dns_addr_request2(nb_dns, (char*) bytes,
				len == 1 ? AF_INET : AF_INET6, (void*) this, err) >= 0;
		}
	}

class DNS_Mapping {
public:
	DNS_Mapping(const char* host, struct hostent* h, uint32_t ttl);
	DNS_Mapping(const IPAddr& addr, struct hostent* h, uint32_t ttl);
	DNS_Mapping(FILE* f);

	int NoMapping() const		{ return no_mapping; }
	int InitFailed() const		{ return init_failed; }

	~DNS_Mapping();

	// Returns nil if this was an address request.
	const char* ReqHost() const	{ return req_host; }
	IPAddr ReqAddr() const		{ return req_addr; }
	string ReqStr() const
		{
		return req_host ? req_host : req_addr.AsString();
		}

	ListVal* Addrs();
	TableVal* AddrsSet();	// addresses returned as a set
	StringVal* Host();

	double CreationTime() const	{ return creation_time; }

	void Save(FILE* f) const;

	int Failed() const		{ return failed; }
	int Valid() const		{ return ! failed; }

	bool Expired() const
		{
		if ( req_host && num_addrs == 0)
			return false; // nothing to expire

		return current_time() > (creation_time + req_ttl);
		}

	int Type() const { return map_type; }

protected:
	friend class DNS_Mgr;

	void Init(struct hostent* h);
	void Clear();

	int no_mapping;	// when initializing from a file, immediately hit EOF
	int init_failed;

	char* req_host;
	IPAddr req_addr;
	uint32_t req_ttl;

	int num_names;
	char** names;
	StringVal* host_val;

	int num_addrs;
	IPAddr* addrs;
	ListVal* addrs_val;

	int failed;
	double creation_time;
	int map_type;
};

void DNS_Mgr_mapping_delete_func(void* v)
	{
	delete (DNS_Mapping*) v;
	}

static TableVal* empty_addr_set()
	{
	BroType* addr_t = base_type(TYPE_ADDR);
	TypeList* set_index = new TypeList(addr_t);
	set_index->Append(addr_t);
	SetType* s = new SetType(set_index, 0);
	return new TableVal(s);
	}

DNS_Mapping::DNS_Mapping(const char* host, struct hostent* h, uint32_t ttl)
	{
	Init(h);
	req_host = copy_string(host);
	req_ttl = ttl;

	if ( names && ! names[0] )
		names[0] = copy_string(host);
	}

DNS_Mapping::DNS_Mapping(const IPAddr& addr, struct hostent* h, uint32_t ttl)
	{
	Init(h);
	req_addr = addr;
	req_host = 0;
	req_ttl = ttl;
	}

DNS_Mapping::DNS_Mapping(FILE* f)
	{
	Clear();
	init_failed = 1;

	req_host = 0;
	req_ttl = 0;
	creation_time = 0;

	char buf[512];

	if ( ! fgets(buf, sizeof(buf), f) )
		{
		no_mapping = 1;
		return;
		}

	char req_buf[512+1], name_buf[512+1];
	int is_req_host;

	if ( sscanf(buf, "%lf %d %512s %d %512s %d %d %" PRIu32, &creation_time,
	     &is_req_host, req_buf, &failed, name_buf, &map_type, &num_addrs,
	     &req_ttl) != 8 )
		return;

	if ( is_req_host )
		req_host = copy_string(req_buf);
	else
		req_addr = IPAddr(req_buf);

	num_names = 1;
	names = new char*[num_names];
	names[0] = copy_string(name_buf);

	if ( num_addrs > 0 )
		{
		addrs = new IPAddr[num_addrs];

		for ( int i = 0; i < num_addrs; ++i )
			{
			if ( ! fgets(buf, sizeof(buf), f) )
				{
				num_addrs = i;
				return;
				}

			char* newline = strchr(buf, '\n');
			if ( newline )
				*newline = '\0';

			addrs[i] = IPAddr(buf);
			}
		}
	else
		addrs = 0;

	init_failed = 0;
	}

DNS_Mapping::~DNS_Mapping()
	{
	delete [] req_host;

	if ( names )
		{
		for ( int i = 0; i < num_names; ++i )
			delete [] names[i];
		delete [] names;
		}

	delete [] addrs;

	Unref(host_val);
	Unref(addrs_val);
	}

ListVal* DNS_Mapping::Addrs()
	{
	if ( failed )
		return 0;

	if ( ! addrs_val )
		{
		ListVal* hv = new ListVal(TYPE_ADDR);
		for ( int i = 0; i < num_addrs; ++i )
			hv->Append(new AddrVal(addrs[i]));
		addrs_val = hv;
		}

	Ref(addrs_val);
	return addrs_val;
	}

TableVal* DNS_Mapping::AddrsSet() {
	ListVal* l = Addrs();

	if ( ! l )
		return empty_addr_set();

	auto rval = l->ConvertToSet();
	Unref(l);
	return rval;
	}

StringVal* DNS_Mapping::Host()
	{
	if ( failed || num_names == 0 || ! names[0] )
		return 0;

	if ( ! host_val )
		host_val = new StringVal(names[0]);

	Ref(host_val);
	return host_val;
	}

void DNS_Mapping::Init(struct hostent* h)
	{
	no_mapping = 0;
	init_failed = 0;
	creation_time = current_time();
	host_val = 0;
	addrs_val = 0;

	if ( ! h )
		{
		Clear();
		return;
		}

	map_type = h->h_addrtype;
	num_names = 1;	// for now, just use official name
	names = new char*[num_names];
	names[0] = h->h_name ? copy_string(h->h_name) : 0;

	for ( num_addrs = 0; h->h_addr_list[num_addrs]; ++num_addrs )
		;

	if ( num_addrs > 0 )
		{
		addrs = new IPAddr[num_addrs];
		for ( int i = 0; i < num_addrs; ++i )
			if ( h->h_addrtype == AF_INET )
				addrs[i] = IPAddr(IPv4, (uint32_t*)h->h_addr_list[i],
				                  IPAddr::Network);
			else if ( h->h_addrtype == AF_INET6 )
				addrs[i] = IPAddr(IPv6, (uint32_t*)h->h_addr_list[i],
				                  IPAddr::Network);
		}
	else
		addrs = 0;

	failed = 0;
	}

void DNS_Mapping::Clear()
	{
	num_names = num_addrs = 0;
	names = 0;
	addrs = 0;
	host_val = 0;
	addrs_val = 0;
	no_mapping = 0;
	map_type = 0;
	failed = 1;
	}

void DNS_Mapping::Save(FILE* f) const
	{
	fprintf(f, "%.0f %d %s %d %s %d %d %" PRIu32"\n", creation_time, req_host != 0,
		req_host ? req_host : req_addr.AsString().c_str(),
		failed, (names && names[0]) ? names[0] : "*",
		map_type, num_addrs, req_ttl);

	for ( int i = 0; i < num_addrs; ++i )
		fprintf(f, "%s\n", addrs[i].AsString().c_str());
	}


DNS_Mgr::DNS_Mgr(DNS_MgrMode arg_mode)
	{
	did_init = 0;

	mode = arg_mode;

	dns_mapping_valid = dns_mapping_unverified = dns_mapping_new_name =
		dns_mapping_lost_name = dns_mapping_name_changed =
			dns_mapping_altered =  0;

	dm_rec = 0;

	cache_name = dir = 0;

	asyncs_pending = 0;
	num_requests = 0;
	successful = 0;
	failed = 0;
	nb_dns = nullptr;
	}

DNS_Mgr::~DNS_Mgr()
	{
	if ( nb_dns )
		nb_dns_finish(nb_dns);

	delete [] cache_name;
	delete [] dir;
	}

void DNS_Mgr::InitSource()
	{
	if ( did_init )
		return;

	// Note that Init() may be called by way of LookupHost() during the act of
	// parsing a hostname literal (e.g. google.com), so we can't use a
	// script-layer option to configure the DNS resolver as it may not be
	// configured to the user's desired address at the time when we need to to
	// the lookup.
	auto dns_resolver = zeekenv("ZEEK_DNS_RESOLVER");
	auto dns_resolver_addr = dns_resolver ? IPAddr(dns_resolver) : IPAddr();
	char err[NB_DNS_ERRSIZE];

	if ( dns_resolver_addr == IPAddr() )
		nb_dns = nb_dns_init(err);
	else
		{
		struct sockaddr_storage ss = {0};

		if ( dns_resolver_addr.GetFamily() == IPv4 )
			{
			struct sockaddr_in* sa = (struct sockaddr_in*)&ss;
			sa->sin_family = AF_INET;
			dns_resolver_addr.CopyIPv4(&sa->sin_addr);
			}
		else
			{
			struct sockaddr_in6* sa = (struct sockaddr_in6*)&ss;
			sa->sin6_family = AF_INET6;
			dns_resolver_addr.CopyIPv6(&sa->sin6_addr);
			}

		nb_dns = nb_dns_init2(err, (struct sockaddr*)&ss);
		}

	if ( nb_dns )
		{
		if ( ! iosource_mgr->RegisterFd(nb_dns_fd(nb_dns), this) )
			reporter->FatalError("Failed to register nb_dns file descriptor with iosource_mgr");
		}
	else
		{
		reporter->Warning("problem initializing NB-DNS: %s", err);
		}

	did_init = true;
	}

void DNS_Mgr::InitPostScript()
	{
	dns_mapping_valid = internal_handler("dns_mapping_valid");
	dns_mapping_unverified = internal_handler("dns_mapping_unverified");
	dns_mapping_new_name = internal_handler("dns_mapping_new_name");
	dns_mapping_lost_name = internal_handler("dns_mapping_lost_name");
	dns_mapping_name_changed = internal_handler("dns_mapping_name_changed");
	dns_mapping_altered = internal_handler("dns_mapping_altered");

	dm_rec = internal_type("dns_mapping")->AsRecordType();

	// Registering will call Init()
	iosource_mgr->Register(this, true);

	const char* cache_dir = dir ? dir : ".";
	cache_name = new char[strlen(cache_dir) + 64];
	sprintf(cache_name, "%s/%s", cache_dir, ".zeek-dns-cache");
	LoadCache(fopen(cache_name, "r"));
	}

static TableVal* fake_name_lookup_result(const char* name)
	{
	uint32_t hash[4];
	internal_md5(reinterpret_cast<const u_char*>(name), strlen(name),
	    reinterpret_cast<u_char*>(hash));
	ListVal* hv = new ListVal(TYPE_ADDR);
	hv->Append(new AddrVal(hash));
	TableVal* tv = hv->ConvertToSet();
	Unref(hv);
	return tv;
	}

static const char* fake_text_lookup_result(const char* name)
	{
	static char tmp[32 + 256];
	snprintf(tmp, sizeof(tmp), "fake_text_lookup_result_%s", name);
	return tmp;
	}

static const char* fake_addr_lookup_result(const IPAddr& addr)
	{
	static char tmp[128];
	snprintf(tmp, sizeof(tmp), "fake_addr_lookup_result_%s",
	         addr.AsString().c_str());
	return tmp;
	}

TableVal* DNS_Mgr::LookupHost(const char* name)
	{
	if ( mode == DNS_FAKE )
		return fake_name_lookup_result(name);

	InitSource();

	if ( ! nb_dns )
		return empty_addr_set();

	if ( mode != DNS_PRIME )
		{
		HostMap::iterator it = host_mappings.find(name);

		if ( it != host_mappings.end() )
			{
			DNS_Mapping* d4 = it->second.first;
			DNS_Mapping* d6 = it->second.second;

			if ( (d4 && d4->Failed()) || (d6 && d6->Failed()) )
				{
				reporter->Warning("no such host: %s", name);
				return empty_addr_set();
				}
			else if ( d4 && d6 )
				{
				TableVal* tv4 = d4->AddrsSet();
				TableVal* tv6 = d6->AddrsSet();
				tv4->AddTo(tv6, false);
				Unref(tv4);
				return tv6;
				}
			}
		}

	// Not found, or priming.
	switch ( mode ) {
	case DNS_PRIME:
		requests.push_back(new DNS_Mgr_Request(name, AF_INET, false));
		requests.push_back(new DNS_Mgr_Request(name, AF_INET6, false));
		return empty_addr_set();

	case DNS_FORCE:
		reporter->FatalError("can't find DNS entry for %s in cache", name);
		return 0;

	case DNS_DEFAULT:
		requests.push_back(new DNS_Mgr_Request(name, AF_INET, false));
		requests.push_back(new DNS_Mgr_Request(name, AF_INET6, false));
		Resolve();
		return LookupHost(name);

	default:
		reporter->InternalError("bad mode in DNS_Mgr::LookupHost");
		return 0;
	}
	}

Val* DNS_Mgr::LookupAddr(const IPAddr& addr)
	{
	InitSource();

	if ( mode != DNS_PRIME )
		{
		AddrMap::iterator it = addr_mappings.find(addr);

		if ( it != addr_mappings.end() )
			{
			DNS_Mapping* d = it->second;
			if ( d->Valid() )
				return d->Host();
			else
				{
				string s(addr);
				reporter->Warning("can't resolve IP address: %s", s.c_str());
				return new StringVal(s.c_str());
				}
			}
		}

	// Not found, or priming.
	switch ( mode ) {
	case DNS_PRIME:
		requests.push_back(new DNS_Mgr_Request(addr));
		return new StringVal("<none>");

	case DNS_FORCE:
		reporter->FatalError("can't find DNS entry for %s in cache",
		    addr.AsString().c_str());
		return 0;

	case DNS_DEFAULT:
		requests.push_back(new DNS_Mgr_Request(addr));
		Resolve();
		return LookupAddr(addr);

	default:
		reporter->InternalError("bad mode in DNS_Mgr::LookupAddr");
		return 0;
	}
	}

void DNS_Mgr::Verify()
	{
	}

#define MAX_PENDING_REQUESTS 20

void DNS_Mgr::Resolve()
	{
	if ( ! nb_dns )
		return;

	int i;

	int first_req = 0;
	int num_pending = min(requests.length(), MAX_PENDING_REQUESTS);
	int last_req = num_pending - 1;

	// Prime with the initial requests.
	for ( i = first_req; i <= last_req; ++i )
		requests[i]->MakeRequest(nb_dns);

	// Start resolving.  Each time an answer comes in, we can issue a
	// new request, if we have more.
	while ( num_pending > 0 )
		{
		int status = AnswerAvailable(DNS_TIMEOUT);

		if ( status <= 0 )
			{
			// Error or timeout.  Process all pending requests as
			// unanswered and reprime.
			for ( i = first_req; i <= last_req; ++i )
				{
				DNS_Mgr_Request* dr = requests[i];
				if ( dr->RequestPending() )
					{
					AddResult(dr, 0);
					dr->RequestDone();
					}
				}

			first_req = last_req + 1;
			num_pending = min(requests.length() - first_req,
						MAX_PENDING_REQUESTS);
			last_req = first_req + num_pending - 1;

			for ( i = first_req; i <= last_req; ++i )
				requests[i]->MakeRequest(nb_dns);

			continue;
			}

		char err[NB_DNS_ERRSIZE];
		struct nb_dns_result r;
		status = nb_dns_activity(nb_dns, &r, err);
		if ( status < 0 )
			reporter->Warning(
			    "NB-DNS error in DNS_Mgr::WaitForReplies (%s)",
			    err);
		else if ( status > 0 )
			{
			DNS_Mgr_Request* dr = (DNS_Mgr_Request*) r.cookie;
			if ( dr->RequestPending() )
				{
				AddResult(dr, &r);
				dr->RequestDone();
				}

			// Room for another, if we have it.
			if ( last_req < requests.length() - 1 )
				{
				++last_req;
				requests[last_req]->MakeRequest(nb_dns);
				}
			else
				--num_pending;
			}
		}

	// All done with the list of requests.
	for ( i = requests.length() - 1; i >= 0; --i )
		delete requests.remove_nth(i);
	}

int DNS_Mgr::Save()
	{
	if ( ! cache_name )
		return 0;

	FILE* f = fopen(cache_name, "w");

	if ( ! f )
		return 0;

	Save(f, host_mappings);
	Save(f, addr_mappings);
	// Save(f, text_mappings); // We don't save the TXT mappings (yet?).

	fclose(f);

	return 1;
	}

void DNS_Mgr::Event(EventHandlerPtr e, DNS_Mapping* dm)
	{
	if ( ! e )
		return;

	mgr.QueueEventFast(e, {BuildMappingVal(dm)});
	}

void DNS_Mgr::Event(EventHandlerPtr e, DNS_Mapping* dm, ListVal* l1, ListVal* l2)
	{
	if ( ! e )
		return;

	Unref(l1);
	Unref(l2);

	mgr.QueueEventFast(e, {
		BuildMappingVal(dm),
		l1->ConvertToSet(),
		l2->ConvertToSet(),
	});
	}

void DNS_Mgr::Event(EventHandlerPtr e, DNS_Mapping* old_dm, DNS_Mapping* new_dm)
	{
	if ( ! e )
		return;

	mgr.QueueEventFast(e, {
		BuildMappingVal(old_dm),
		BuildMappingVal(new_dm),
	});
	}

Val* DNS_Mgr::BuildMappingVal(DNS_Mapping* dm)
	{
	RecordVal* r = new RecordVal(dm_rec);

	r->Assign(0, new Val(dm->CreationTime(), TYPE_TIME));
	r->Assign(1, new StringVal(dm->ReqHost() ? dm->ReqHost() : ""));
	r->Assign(2, new AddrVal(dm->ReqAddr()));
	r->Assign(3, val_mgr->GetBool(dm->Valid()));

	Val* h = dm->Host();
	r->Assign(4, h ? h : new StringVal("<none>"));
	r->Assign(5, dm->AddrsSet());

	return r;
	}

void DNS_Mgr::AddResult(DNS_Mgr_Request* dr, struct nb_dns_result* r)
	{
	struct hostent* h = (r && r->host_errno == 0) ? r->hostent : 0;
	u_int32_t ttl = (r && r->host_errno == 0) ? r->ttl : 0;

	DNS_Mapping* new_dm;
	DNS_Mapping* prev_dm;
	int keep_prev = 0;

	if ( dr->ReqHost() )
		{
		new_dm = new DNS_Mapping(dr->ReqHost(), h, ttl);
		prev_dm = 0;

		if ( dr->ReqIsTxt() )
			{
			TextMap::iterator it = text_mappings.find(dr->ReqHost());

			if ( it == text_mappings.end() )
				text_mappings[dr->ReqHost()] = new_dm;
			else
				{
				prev_dm = it->second;
				it->second = new_dm;
				}

			if ( new_dm->Failed() && prev_dm && prev_dm->Valid() )
				{
				text_mappings[dr->ReqHost()] = prev_dm;
				++keep_prev;
				}
			}
		else
			{
			HostMap::iterator it = host_mappings.find(dr->ReqHost());
			if ( it == host_mappings.end() )
				{
				host_mappings[dr->ReqHost()].first =
					new_dm->Type() == AF_INET ? new_dm : 0;

				host_mappings[dr->ReqHost()].second =
					new_dm->Type() == AF_INET ? 0 : new_dm;
				}
			else
				{
				if ( new_dm->Type() == AF_INET )
					{
					prev_dm = it->second.first;
					it->second.first = new_dm;
					}
				else
					{
					prev_dm = it->second.second;
					it->second.second = new_dm;
					}
				}

			if ( new_dm->Failed() && prev_dm && prev_dm->Valid() )
				{
				// Put previous, valid entry back - CompareMappings
				// will generate a corresponding warning.
				if ( prev_dm->Type() == AF_INET )
					host_mappings[dr->ReqHost()].first = prev_dm;
				else
					host_mappings[dr->ReqHost()].second = prev_dm;

				++keep_prev;
				}
			}
		}
	else
		{
		new_dm = new DNS_Mapping(dr->ReqAddr(), h, ttl);
		AddrMap::iterator it = addr_mappings.find(dr->ReqAddr());
		prev_dm = (it == addr_mappings.end()) ? 0 : it->second;
		addr_mappings[dr->ReqAddr()] = new_dm;

		if ( new_dm->Failed() && prev_dm && prev_dm->Valid() )
			{
			addr_mappings[dr->ReqAddr()] = prev_dm;
			++keep_prev;
			}
		}

	if ( prev_dm && ! dr->ReqIsTxt() )
		CompareMappings(prev_dm, new_dm);

	if ( keep_prev )
		delete new_dm;
	else
		delete prev_dm;
	}

void DNS_Mgr::CompareMappings(DNS_Mapping* prev_dm, DNS_Mapping* new_dm)
	{
	if ( prev_dm->Failed() )
		{
		if ( new_dm->Failed() )
			// Nothing changed.
			return;

		Event(dns_mapping_valid, new_dm);
		return;
		}

	else if ( new_dm->Failed() )
		{
		Event(dns_mapping_unverified, prev_dm);
		return;
		}

	StringVal* prev_s = prev_dm->Host();
	StringVal* new_s = new_dm->Host();

	if ( prev_s || new_s )
		{
		if ( ! prev_s )
			Event(dns_mapping_new_name, new_dm);
		else if ( ! new_s )
			Event(dns_mapping_lost_name, prev_dm);
		else if ( ! Bstr_eq(new_s->AsString(), prev_s->AsString()) )
			Event(dns_mapping_name_changed, prev_dm, new_dm);

		Unref(prev_s);
		Unref(new_s);
		}

	ListVal* prev_a = prev_dm->Addrs();
	ListVal* new_a = new_dm->Addrs();

	if ( ! prev_a || ! new_a )
		{
		reporter->InternalWarning("confused in DNS_Mgr::CompareMappings");
		return;
		}

	ListVal* prev_delta = AddrListDelta(prev_a, new_a);
	ListVal* new_delta = AddrListDelta(new_a, prev_a);

	if ( prev_delta->Length() > 0 || new_delta->Length() > 0 )
		Event(dns_mapping_altered, new_dm, prev_delta, new_delta);
	else
		{
		Unref(prev_delta);
		Unref(new_delta);
		}
	}

ListVal* DNS_Mgr::AddrListDelta(ListVal* al1, ListVal* al2)
	{
	ListVal* delta = new ListVal(TYPE_ADDR);

	for ( int i = 0; i < al1->Length(); ++i )
		{
		const IPAddr& al1_i = al1->Index(i)->AsAddr();

		int j;
		for ( j = 0; j < al2->Length(); ++j )
			{
			const IPAddr& al2_j = al2->Index(j)->AsAddr();
			if ( al1_i == al2_j )
				break;
			}

		if ( j >= al2->Length() )
			// Didn't find it.
			delta->Append(al1->Index(i)->Ref());
		}

	return delta;
	}

void DNS_Mgr::DumpAddrList(FILE* f, ListVal* al)
	{
	for ( int i = 0; i < al->Length(); ++i )
		{
		const IPAddr& al_i = al->Index(i)->AsAddr();
		fprintf(f, "%s%s", i > 0 ? "," : "", al_i.AsString().c_str());
		}
	}

void DNS_Mgr::LoadCache(FILE* f)
	{
	if ( ! f )
		return;

	DNS_Mapping* m = new DNS_Mapping(f);
	for ( ; ! m->NoMapping() && ! m->InitFailed(); m = new DNS_Mapping(f) )
		{
		if ( m->ReqHost() )
			{
			if ( host_mappings.find(m->ReqHost()) == host_mappings.end() )
				{
				host_mappings[m->ReqHost()].first = 0;
				host_mappings[m->ReqHost()].second = 0;
				}
			if ( m->Type() == AF_INET )
				host_mappings[m->ReqHost()].first = m;
			else
				host_mappings[m->ReqHost()].second = m;
			}
		else
			{
			addr_mappings[m->ReqAddr()] = m;
			}
		}

	if ( ! m->NoMapping() )
		reporter->FatalError("DNS cache corrupted");

	delete m;
	fclose(f);
	}

void DNS_Mgr::Save(FILE* f, const AddrMap& m)
	{
	for ( AddrMap::const_iterator it = m.begin(); it != m.end(); ++it )
		{
		if ( it->second )
			it->second->Save(f);
		}
	}

void DNS_Mgr::Save(FILE* f, const HostMap& m)
	{
	HostMap::const_iterator it;

	for ( it = m.begin(); it != m.end(); ++it )
		{
		if ( it->second.first )
			it->second.first->Save(f);

		if ( it->second.second )
			it->second.second->Save(f);
		}
	}

const char* DNS_Mgr::LookupAddrInCache(const IPAddr& addr)
	{
	AddrMap::iterator it = addr_mappings.find(addr);

	if ( it == addr_mappings.end() )
		return 0;

	DNS_Mapping* d = it->second;

	if ( d->Expired() )
		{
		addr_mappings.erase(it);
		delete d;
		return 0;
		}

	// The escapes in the following strings are to avoid having it
	// interpreted as a trigraph sequence.
	return d->names ? d->names[0] : "<\?\?\?>";
	}

TableVal* DNS_Mgr::LookupNameInCache(const string& name)
	{
	HostMap::iterator it = host_mappings.find(name);
	if ( it == host_mappings.end() )
		{
		it = host_mappings.begin();
		return 0;
		}

	DNS_Mapping* d4 = it->second.first;
	DNS_Mapping* d6 = it->second.second;

	if ( ! d4 || ! d4->names || ! d6 || ! d6->names )
		return 0;

	if ( d4->Expired() || d6->Expired() )
		{
		host_mappings.erase(it);
		delete d4;
		delete d6;
		return 0;
		}

	TableVal* tv4 = d4->AddrsSet();
	TableVal* tv6 = d6->AddrsSet();
	tv4->AddTo(tv6, false);
	Unref(tv4);
	return tv6;
	}

const char* DNS_Mgr::LookupTextInCache(const string& name)
	{
	TextMap::iterator it = text_mappings.find(name);
	if ( it == text_mappings.end() )
		return 0;

	DNS_Mapping* d = it->second;

	if ( d->Expired() )
		{
		text_mappings.erase(it);
		delete d;
		return 0;
		}

	// The escapes in the following strings are to avoid having it
	// interpreted as a trigraph sequence.
	return d->names ? d->names[0] : "<\?\?\?>";
	}

static void resolve_lookup_cb(DNS_Mgr::LookupCallback* callback,
                              TableVal* result)
	{
	callback->Resolved(result);
	Unref(result);
	delete callback;
	}

static void resolve_lookup_cb(DNS_Mgr::LookupCallback* callback,
                              const char* result)
	{
	callback->Resolved(result);
	delete callback;
	}

void DNS_Mgr::AsyncLookupAddr(const IPAddr& host, LookupCallback* callback)
	{
	InitSource();

	if ( mode == DNS_FAKE )
		{
		resolve_lookup_cb(callback, fake_addr_lookup_result(host));
		return;
		}

	// Do we already know the answer?
	const char* name = LookupAddrInCache(host);
	if ( name )
		{
		resolve_lookup_cb(callback, name);
		return;
		}

	AsyncRequest* req = 0;

	// Have we already a request waiting for this host?
	AsyncRequestAddrMap::iterator i = asyncs_addrs.find(host);
	if ( i != asyncs_addrs.end() )
		req = i->second;
	else
		{
		// A new one.
		req = new AsyncRequest;
		req->host = host;
		asyncs_queued.push_back(req);
		asyncs_addrs.insert(AsyncRequestAddrMap::value_type(host, req));
		}

	req->callbacks.push_back(callback);

	IssueAsyncRequests();
	}

void DNS_Mgr::AsyncLookupName(const string& name, LookupCallback* callback)
	{
	InitSource();

	if ( mode == DNS_FAKE )
		{
		resolve_lookup_cb(callback, fake_name_lookup_result(name.c_str()));
		return;
		}

	// Do we already know the answer?
	TableVal* addrs = LookupNameInCache(name);
	if ( addrs )
		{
		resolve_lookup_cb(callback, addrs);
		return;
		}

	AsyncRequest* req = 0;

	// Have we already a request waiting for this host?
	AsyncRequestNameMap::iterator i = asyncs_names.find(name);
	if ( i != asyncs_names.end() )
		req = i->second;
	else
		{
		// A new one.
		req = new AsyncRequest;
		req->name = name;
		asyncs_queued.push_back(req);
		asyncs_names.insert(AsyncRequestNameMap::value_type(name, req));
		}

	req->callbacks.push_back(callback);

	IssueAsyncRequests();
	}

void DNS_Mgr::AsyncLookupNameText(const string& name, LookupCallback* callback)
	{
	InitSource();

	if ( mode == DNS_FAKE )
		{
		resolve_lookup_cb(callback, fake_text_lookup_result(name.c_str()));
		return;
		}

	// Do we already know the answer?
	const char* txt = LookupTextInCache(name);

	if ( txt )
		{
		resolve_lookup_cb(callback, txt);
		return;
		}

	AsyncRequest* req = 0;

	// Have we already a request waiting for this host?
	AsyncRequestTextMap::iterator i = asyncs_texts.find(name);
	if ( i != asyncs_texts.end() )
		req = i->second;
	else
		{
		// A new one.
		req = new AsyncRequest;
		req->name = name;
		req->is_txt = true;
		asyncs_queued.push_back(req);
		asyncs_texts.insert(AsyncRequestTextMap::value_type(name, req));
		}

	req->callbacks.push_back(callback);

	IssueAsyncRequests();
	}

static bool DoRequest(nb_dns_info* nb_dns, DNS_Mgr_Request* dr)
	{
	if ( dr->MakeRequest(nb_dns) )
		// dr stored in nb_dns cookie and deleted later when results available.
		return true;

	reporter->Warning("can't issue DNS request");
	delete dr;
	return false;
	}

void DNS_Mgr::IssueAsyncRequests()
	{
	while ( asyncs_queued.size() && asyncs_pending < MAX_PENDING_REQUESTS )
		{
		AsyncRequest* req = asyncs_queued.front();
		asyncs_queued.pop_front();

		++num_requests;

		bool success;

		if ( req->IsAddrReq() )
			success = DoRequest(nb_dns, new DNS_Mgr_Request(req->host));
		else if ( req->is_txt )
			success = DoRequest(nb_dns, new DNS_Mgr_Request(req->name.c_str(),
			                                AF_INET, req->is_txt));
		else
			{
			// If only one request type succeeds, don't consider it a failure.
			success = DoRequest(nb_dns, new DNS_Mgr_Request(req->name.c_str(),
			                                AF_INET, req->is_txt));
			success = DoRequest(nb_dns, new DNS_Mgr_Request(req->name.c_str(),
			                                AF_INET6, req->is_txt)) || success;
			}

		if ( ! success )
			{
			req->Timeout();
			++failed;
			continue;
			}

		req->time = current_time();
		asyncs_timeouts.push(req);

		++asyncs_pending;
		}
	}

void DNS_Mgr::CheckAsyncAddrRequest(const IPAddr& addr, bool timeout)
	{
	// Note that this code is a mirror of that for CheckAsyncHostRequest.

	// In the following, if it's not in the respective map anymore, we've
	// already finished it earlier and don't have anything to do.
	AsyncRequestAddrMap::iterator i = asyncs_addrs.find(addr);

	if ( i != asyncs_addrs.end() )
		{
		const char* name = LookupAddrInCache(addr);
		if ( name )
			{
			++successful;
			i->second->Resolved(name);
			}

		else if ( timeout )
			{
			++failed;
			i->second->Timeout();
			}

		else
			return;

		asyncs_addrs.erase(i);
		--asyncs_pending;

		// Don't delete the request.  That will be done once it
		// eventually times out.
		}

	}

void DNS_Mgr::CheckAsyncTextRequest(const char* host, bool timeout)
	{
	// Note that this code is a mirror of that for CheckAsyncAddrRequest.

	AsyncRequestTextMap::iterator i = asyncs_texts.find(host);
	if ( i != asyncs_texts.end() )
		{
		const char* name = LookupTextInCache(host);
		if ( name )
			{
			++successful;
			i->second->Resolved(name);
			}

		else if ( timeout )
			{
			AsyncRequestTextMap::iterator it = asyncs_texts.begin();
			++failed;
			i->second->Timeout();
			}

		else
			return;

		asyncs_texts.erase(i);
		--asyncs_pending;

		// Don't delete the request.  That will be done once it
		// eventually times out.
		}
	}

void DNS_Mgr::CheckAsyncHostRequest(const char* host, bool timeout)
	{
	// Note that this code is a mirror of that for CheckAsyncAddrRequest.

	AsyncRequestNameMap::iterator i = asyncs_names.find(host);

	if ( i != asyncs_names.end() )
		{
		TableVal* addrs = LookupNameInCache(host);

		if ( addrs )
			{
			++successful;
			i->second->Resolved(addrs);
			Unref(addrs);
			}

		else if ( timeout )
			{
			++failed;
			i->second->Timeout();
			}

		else
			return;

		asyncs_names.erase(i);
		--asyncs_pending;

		// Don't delete the request.  That will be done once it
		// eventually times out.
		}
	}

void DNS_Mgr::Flush()
	{
	Process();

	HostMap::iterator it;
	for ( it = host_mappings.begin(); it != host_mappings.end(); ++it )
		{
		delete it->second.first;
		delete it->second.second;
		}

	for ( AddrMap::iterator it2 = addr_mappings.begin(); it2 != addr_mappings.end(); ++it2 )
		delete it2->second;

	for ( TextMap::iterator it3 = text_mappings.begin(); it3 != text_mappings.end(); ++it3 )
		delete it3->second;

	host_mappings.clear();
	addr_mappings.clear();
	text_mappings.clear();
	}

double DNS_Mgr::GetNextTimeout()
	{
	if ( asyncs_timeouts.empty() )
		return -1;

	return network_time + DNS_TIMEOUT;
	}

void DNS_Mgr::Process()
	{
	if ( ! nb_dns )
		return;

	while ( asyncs_timeouts.size() > 0 )
		{
		AsyncRequest* req = asyncs_timeouts.top();

		if ( req->time + DNS_TIMEOUT > current_time() && ! terminating )
			break;

		if ( ! req->processed )
			{
			if ( req->IsAddrReq() )
				CheckAsyncAddrRequest(req->host, true);
			else if ( req->is_txt )
				CheckAsyncTextRequest(req->name.c_str(), true);
			else
				CheckAsyncHostRequest(req->name.c_str(), true);
			}

		asyncs_timeouts.pop();
		delete req;
		}

	if ( AnswerAvailable(0) <= 0 )
		return;

	char err[NB_DNS_ERRSIZE];
	struct nb_dns_result r;

	int status = nb_dns_activity(nb_dns, &r, err);

	if ( status < 0 )
		reporter->Warning("NB-DNS error in DNS_Mgr::Process (%s)", err);

	else if ( status > 0 )
		{
		DNS_Mgr_Request* dr = (DNS_Mgr_Request*) r.cookie;

		bool do_host_timeout = true;
		if ( dr->ReqHost() &&
		     host_mappings.find(dr->ReqHost()) == host_mappings.end() )
			// Don't timeout when this is the first result in an expected pair
			// (one result each for A and AAAA queries).
			do_host_timeout = false;

		if ( dr->RequestPending() )
			{
			AddResult(dr, &r);
			dr->RequestDone();
			}

		if ( ! dr->ReqHost() )
			CheckAsyncAddrRequest(dr->ReqAddr(), true);
		else if ( dr->ReqIsTxt() )
			CheckAsyncTextRequest(dr->ReqHost(), do_host_timeout);
		else
			CheckAsyncHostRequest(dr->ReqHost(), do_host_timeout);

		IssueAsyncRequests();

		delete dr;
		}
	}

int DNS_Mgr::AnswerAvailable(int timeout)
	{
	if ( ! nb_dns )
		return -1;

	int fd = nb_dns_fd(nb_dns);
	if ( fd < 0 )
		{
		reporter->Warning("nb_dns_fd() failed in DNS_Mgr::WaitForReplies");
		return -1;
		}

	fd_set read_fds;

	FD_ZERO(&read_fds);
	FD_SET(fd, &read_fds);

	struct timeval t;
	t.tv_sec = timeout;
	t.tv_usec = 0;

	int status = select(fd+1, &read_fds, 0, 0, &t);

	if ( status < 0 )
		{
		if ( errno != EINTR )
			reporter->Warning("problem with DNS select");

		return -1;
		}

	if ( status > 1 )
		{
		reporter->Warning("strange return from DNS select");
		return -1;
		}

	return status;
	}

void DNS_Mgr::GetStats(Stats* stats)
	{
	stats->requests = num_requests;
	stats->successful = successful;
	stats->failed = failed;
	stats->pending = asyncs_pending;
	stats->cached_hosts = host_mappings.size();
	stats->cached_addresses = addr_mappings.size();
	stats->cached_texts = text_mappings.size();
	}

void DNS_Mgr::Terminate()
	{
	if ( nb_dns )
		iosource_mgr->UnregisterFd(nb_dns_fd(nb_dns), this);
	}
