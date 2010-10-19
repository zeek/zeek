// $Id: DNS_Mgr.cc 7073 2010-09-13 00:45:02Z vern $
//
// See the file "COPYING" in the main distribution directory for copyright.

#include "config.h"

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

#include "DNS_Mgr.h"
#include "Event.h"
#include "Net.h"
#include "Var.h"

extern "C" {
extern int select(int, fd_set *, fd_set *, fd_set *, struct timeval *);

#include <netdb.h>

#include "nb_dns.h"
}


class DNS_Mgr_Request {
public:
	DNS_Mgr_Request(const char* h)	{ host = copy_string(h); addr = 0; }
	DNS_Mgr_Request(uint32 a)		{ addr = a; host = 0; }
	~DNS_Mgr_Request()			{ delete [] host; }

	// Returns nil if this was an address request.
	const char* ReqHost() const	{ return host; }
	uint32 ReqAddr() const		{ return addr; }

	int MakeRequest(nb_dns_info* nb_dns);
	int RequestPending() const	{ return request_pending; }
	void RequestDone()	{ request_pending = 0; }


protected:
	char* host;	// if non-nil, this is a host request
	uint32 addr;
	int request_pending;
};

int DNS_Mgr_Request::MakeRequest(nb_dns_info* nb_dns)
	{
	if ( ! nb_dns )
		return 0;

	request_pending = 1;

	char err[NB_DNS_ERRSIZE];
	if ( host )
		return nb_dns_host_request(nb_dns, host, (void*) this, err) >= 0;
	else
		return nb_dns_addr_request(nb_dns, addr, (void*) this, err) >= 0;
	}

class DNS_Mapping {
public:
	DNS_Mapping(const char* host, struct hostent* h);
	DNS_Mapping(uint32 addr, struct hostent* h);
	DNS_Mapping(FILE* f);

	int NoMapping() const		{ return no_mapping; }
	int InitFailed() const		{ return init_failed; }

	~DNS_Mapping();

	// Returns nil if this was an address request.
	const char* ReqHost() const	{ return req_host; }
	uint32 ReqAddr() const		{ return req_addr; }
	const char* ReqStr() const
		{ return req_host ? req_host : dotted_addr(ReqAddr());  }

	ListVal* Addrs();
	TableVal* AddrsSet();	// addresses returned as a set
	StringVal* Host();

	double CreationTime() const	{ return creation_time; }

	void Save(FILE* f) const;

	int Failed() const		{ return failed; }
	int Valid() const		{ return ! failed; }

protected:
	friend class DNS_Mgr;

	void Init(struct hostent* h);
	void Clear();

	int no_mapping;	// when initializing from a file, immediately hit EOF
	int init_failed;

	char* req_host;
	uint32 req_addr;

	int num_names;
	char** names;
	StringVal* host_val;

	int num_addrs;
	uint32* addrs;
	ListVal* addrs_val;

	int failed;
	double creation_time;
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

DNS_Mapping::DNS_Mapping(const char* host, struct hostent* h)
	{
	Init(h);
	req_host = copy_string(host);
	req_addr = 0;

	if ( names && ! names[0] )
		names[0] = copy_string(host);
	}

DNS_Mapping::DNS_Mapping(uint32 addr, struct hostent* h)
	{
	Init(h);
	req_addr = addr;
	req_host = 0;
	}

DNS_Mapping::DNS_Mapping(FILE* f)
	{
	Clear();
	init_failed = 1;

	req_host = 0;
	req_addr = 0;

	char buf[512];

	if ( ! fgets(buf, sizeof(buf), f) )
		{
		no_mapping = 1;
		return;
		}

	char req_buf[512+1], name_buf[512+1];
	int is_req_host;

	if ( sscanf(buf, "%lf %d %512s %d %512s %d", &creation_time, &is_req_host,
		    req_buf, &failed, name_buf, &num_addrs) != 6 )
		return;

	if ( is_req_host )
		req_host = copy_string(req_buf);
	else
		req_addr = dotted_to_addr(req_buf);

	num_names = 1;
	names = new char*[num_names];
	names[0] = copy_string(name_buf);

	if ( num_addrs > 0 )
		{
		addrs = new uint32[num_addrs];

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

			addrs[i] = dotted_to_addr(buf);
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
	if ( l )
		return l->ConvertToSet();
	else
		return empty_addr_set();
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

// Converts an array of 4 bytes in network order to the corresponding
// 32-bit network long.
static uint32 raw_bytes_to_addr(const unsigned char b[4])
	{
	uint32 l = (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3];
	return uint32(htonl(l));
	}

void DNS_Mapping::Init(struct hostent* h)
	{
	no_mapping = 0;
	init_failed = 0;
	creation_time = current_time();
	host_val = 0;
	addrs_val = 0;

	if ( ! h || h->h_addrtype != AF_INET || h->h_length != 4 )
		{
		Clear();
		return;
		}

	num_names = 1;	// for now, just use official name
	names = new char*[num_names];
	names[0] = h->h_name ? copy_string(h->h_name) : 0;

	for ( num_addrs = 0; h->h_addr_list[num_addrs]; ++num_addrs )
		;

	if ( num_addrs > 0 )
		{
		addrs = new uint32[num_addrs];
		for ( int i = 0; i < num_addrs; ++i )
			addrs[i] = raw_bytes_to_addr(
					(unsigned char*)h->h_addr_list[i]);
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
	failed = 1;
	}

void DNS_Mapping::Save(FILE* f) const
	{
	fprintf(f, "%.0f %d %s %d %s %d\n", creation_time, req_host != 0,
		req_host ? req_host : dotted_addr(req_addr),
		failed, (names && names[0]) ? names[0] : "*",
		num_addrs);

	for ( int i = 0; i < num_addrs; ++i )
		fprintf(f, "%s\n", dotted_addr(addrs[i]));
	}


DNS_Mgr::DNS_Mgr(DNS_MgrMode arg_mode)
	{
	did_init = 0;

	mode = arg_mode;

	host_mappings.SetDeleteFunc(DNS_Mgr_mapping_delete_func);
	addr_mappings.SetDeleteFunc(DNS_Mgr_mapping_delete_func);

	char err[NB_DNS_ERRSIZE];
	nb_dns = nb_dns_init(err);

	if ( ! nb_dns )
		warn(fmt("problem initializing NB-DNS: %s", err));

	dns_mapping_valid = dns_mapping_unverified = dns_mapping_new_name =
		dns_mapping_lost_name = dns_mapping_name_changed =
			dns_mapping_altered =  0;

	dm_rec = 0;
	dns_fake_count = 0;

	cache_name = dir = 0;

	asyncs_pending = 0;
	}

DNS_Mgr::~DNS_Mgr()
	{
	if ( nb_dns )
		nb_dns_finish(nb_dns);

	delete [] cache_name;
	delete [] dir;
	}

bool DNS_Mgr::Init()
	{
	if ( did_init )
		return true;

	const char* cache_dir = dir ? dir : ".";

	if ( mode == DNS_PRIME && ! ensure_dir(cache_dir) )
		{
		did_init = 0;
		return false;
		}

	cache_name = new char[strlen(cache_dir) + 64];
	sprintf(cache_name, "%s/%s", cache_dir, ".bro-dns-cache");

	LoadCache(fopen(cache_name, "r"));

	dns_mapping_valid = internal_handler("dns_mapping_valid");
	dns_mapping_unverified = internal_handler("dns_mapping_unverified");
	dns_mapping_new_name = internal_handler("dns_mapping_new_name");
	dns_mapping_lost_name = internal_handler("dns_mapping_lost_name");
	dns_mapping_name_changed = internal_handler("dns_mapping_name_changed");
	dns_mapping_altered = internal_handler("dns_mapping_altered");

	dm_rec = internal_type("dns_mapping")->AsRecordType();

	did_init = 1;

	io_sources.Register(this, true);

	// We never set idle to false, having the main loop only calling us from
	// time to time. If we're issuing more DNS requests than we can handle
	// in this way, we are having problems anyway ...
	idle = true;

	return true;
	}

TableVal* DNS_Mgr::LookupHost(const char* name)
	{
	if ( ! nb_dns )
		return empty_addr_set();

	if ( ! did_init )
		Init();

	if ( mode == DNS_FAKE )
		{
		ListVal* hv = new ListVal(TYPE_ADDR);
		hv->Append(new AddrVal(uint32(++dns_fake_count)));
		return hv->ConvertToSet();
		}

	if ( mode != DNS_PRIME )
		{
		DNS_Mapping* d = host_mappings.Lookup(name);

		if ( d )
			{
			if ( d->Valid() )
				return d->Addrs()->ConvertToSet();
			else
				{
				warn("no such host:", name);
				return empty_addr_set();
				}
			}
		}

	// Not found, or priming.
	switch ( mode ) {
	case DNS_PRIME:
		requests.append(new DNS_Mgr_Request(name));
		return empty_addr_set();

	case DNS_FORCE:
		internal_error("can't find DNS entry for %s in cache", name);
		return 0;

	case DNS_DEFAULT:
		requests.append(new DNS_Mgr_Request(name));
		Resolve();
		return LookupHost(name);

	default:
		internal_error("bad mode in DNS_Mgr::LookupHost");
		return 0;
	}
	}

Val* DNS_Mgr::LookupAddr(uint32 addr)
	{
	if ( ! did_init )
		Init();

	if ( mode != DNS_PRIME )
		{
		HashKey h(&addr, 1);
		DNS_Mapping* d = addr_mappings.Lookup(&h);

		if ( d )
			{
			if ( d->Valid() )
				return d->Host();
			else
				{
				warn("can't resolve IP address:", dotted_addr(addr));
				return new StringVal(dotted_addr(addr));
				}
			}
		}

	// Not found, or priming.
	switch ( mode ) {
	case DNS_PRIME:
		requests.append(new DNS_Mgr_Request(addr));
		return new StringVal("<none>");

	case DNS_FORCE:
		internal_error("can't find DNS entry for %s in cache",
				dotted_addr(addr));
		return 0;

	case DNS_DEFAULT:
		requests.append(new DNS_Mgr_Request(addr));
		Resolve();
		return LookupAddr(addr);

	default:
		internal_error("bad mode in DNS_Mgr::LookupHost");
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
			internal_error(
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

	fclose(f);

	return 1;
	}

void DNS_Mgr::Event(EventHandlerPtr e, DNS_Mapping* dm, ListVal* l1, ListVal* l2)
	{
	if ( ! e )
		return;

	val_list* vl = new val_list;
	vl->append(BuildMappingVal(dm));

	if ( l1 )
		{
		vl->append(l1->ConvertToSet());
		if ( l2 )
			vl->append(l2->ConvertToSet());

		Unref(l1);
		Unref(l2);
		}

	mgr.QueueEvent(e, vl);
	}

void DNS_Mgr::Event(EventHandlerPtr e, DNS_Mapping* old_dm, DNS_Mapping* new_dm)
	{
	if ( ! e )
		return;

	val_list* vl = new val_list;
	vl->append(BuildMappingVal(old_dm));
	vl->append(BuildMappingVal(new_dm));
	mgr.QueueEvent(e, vl);
	}

Val* DNS_Mgr::BuildMappingVal(DNS_Mapping* dm)
	{
	RecordVal* r = new RecordVal(dm_rec);

	r->Assign(0, new Val(dm->CreationTime(), TYPE_TIME));
	r->Assign(1, new StringVal(dm->ReqHost() ? dm->ReqHost() : ""));
	r->Assign(2, new AddrVal(dm->ReqAddr()));
	r->Assign(3, new Val(dm->Valid(), TYPE_BOOL));

	Val* h = dm->Host();
	r->Assign(4, h ? h : new StringVal("<none>"));
	r->Assign(5, dm->AddrsSet());

	return r;
	}

void DNS_Mgr::AddResult(DNS_Mgr_Request* dr, struct nb_dns_result* r)
	{
	struct hostent* h = (r && r->host_errno == 0) ? r->hostent : 0;

	DNS_Mapping* new_dm;
	DNS_Mapping* prev_dm;
	int keep_prev = 0;

	if ( dr->ReqHost() )
		{
		new_dm = new DNS_Mapping(dr->ReqHost(), h);
		prev_dm = host_mappings.Insert(dr->ReqHost(), new_dm);

		if ( new_dm->Failed() && prev_dm && prev_dm->Valid() )
			{
			// Put previous, valid entry back - CompareMappings
			// will generate a corresponding warning.
			(void) host_mappings.Insert(dr->ReqHost(), prev_dm);
			++keep_prev;
			}
		}
	else
		{
		new_dm = new DNS_Mapping(dr->ReqAddr(), h);
		uint32 tmp_addr = dr->ReqAddr();
		HashKey k(&tmp_addr, 1);
		prev_dm = addr_mappings.Insert(&k, new_dm);

		if ( new_dm->Failed() && prev_dm && prev_dm->Valid() )
			{
			uint32 tmp_addr = dr->ReqAddr();
			HashKey k2(&tmp_addr, 1);
			(void) addr_mappings.Insert(&k2, prev_dm);
			++keep_prev;
			}
		}

	if ( prev_dm )
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
		internal_error("confused in DNS_Mgr::CompareMappings");

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
		addr_type al1_i = al1->Index(i)->AsAddr();

		int j;
		for ( j = 0; j < al2->Length(); ++j )
			{
			addr_type al2_j = al2->Index(j)->AsAddr();
#ifdef BROv6
			if ( addr_eq(al1_i, al2_j) )
#else
			if ( al1_i == al2_j )
#endif
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
		addr_type al_i = al->Index(i)->AsAddr();
		fprintf(f, "%s%s", i > 0 ? "," : "", dotted_addr(al_i));
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
			host_mappings.Insert(m->ReqHost(), m);
		else
			{
			uint32 tmp_addr = m->ReqAddr();
			HashKey h(&tmp_addr, 1);
			addr_mappings.Insert(&h, m);
			}
		}

	if ( ! m->NoMapping() )
		internal_error("DNS cache corrupted");

	delete m;
	fclose(f);
	}

void DNS_Mgr::Save(FILE* f, PDict(DNS_Mapping)& m)
	{
	IterCookie* cookie = m.InitForIteration();
	DNS_Mapping* dm;

	while ( (dm = m.NextEntry(cookie)) )
		dm->Save(f);
	}

const char* DNS_Mgr::LookupAddrInCache(dns_mgr_addr_type addr)
	{
	HashKey h(&addr, 1);
	DNS_Mapping* d = dns_mgr->addr_mappings.Lookup(&h);
	if ( ! d )
		return 0;

	// The escapes in the following strings are to avoid having it
	// interpreted as a trigraph sequence.
	return d->names ? d->names[0] : "<\?\?\?>";
	}

TableVal* DNS_Mgr::LookupNameInCache(string name)
	{
	DNS_Mapping* d = dns_mgr->host_mappings.Lookup(name.c_str());
	if ( ! d || ! d->names )
		return 0;

	return d->AddrsSet();
	}

void DNS_Mgr::AsyncLookupAddr(dns_mgr_addr_type host, LookupCallback* callback)
	{
	if ( ! did_init )
		Init();

	// Do we already know the answer?
	const char* name = LookupAddrInCache(host);
	if ( name )
		{
		callback->Resolved(name);
		delete callback;
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

void DNS_Mgr::AsyncLookupName(string name, LookupCallback* callback)
	{
	if ( ! did_init )
		Init();

	// Do we already know the answer?
	TableVal* addrs = LookupNameInCache(name);
	if ( addrs )
		{
		callback->Resolved(addrs);
		Unref(addrs);
		delete callback;
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

void DNS_Mgr::IssueAsyncRequests()
	{
	while ( asyncs_queued.size() && asyncs_pending < MAX_PENDING_REQUESTS )
		{
		AsyncRequest* req = asyncs_queued.front();
		asyncs_queued.pop_front();

		DNS_Mgr_Request* dr;
		if ( req->IsAddrReq() )
			dr = new DNS_Mgr_Request(req->host);
		else
			dr = new DNS_Mgr_Request(req->name.c_str());

		if ( ! dr->MakeRequest(nb_dns) )
			{
			run_time("can't issue DNS request");
			req->Timeout();
			continue;
			}

		req->time = current_time();
		asyncs_timeouts.push(req);

		++asyncs_pending;
		}
	}

void  DNS_Mgr::GetFds(int* read, int* write, int* except)
	{
	*read = nb_dns_fd(nb_dns);
	}

double DNS_Mgr::NextTimestamp(double* network_time)
	{
	// This is kind of cheating ...
	return asyncs_timeouts.size() ? timer_mgr->Time() : -1.0;
	}

void DNS_Mgr::CheckAsyncAddrRequest(dns_mgr_addr_type addr, bool timeout)
	{
	// Note that this code is a mirror of that for CheckAsyncHostRequest.

	// In the following, if it's not in the respective map anymore, we've
	// already finished it earlier and don't have anything to do.
	AsyncRequestAddrMap::iterator i = asyncs_addrs.find(addr);

	if ( i != asyncs_addrs.end() )
		{
		const char* name = LookupAddrInCache(addr);
		if ( name )
			i->second->Resolved(name);

		else if ( timeout )
			i->second->Timeout();

		else
			return;

		asyncs_addrs.erase(i);
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
			i->second->Resolved(addrs);
			Unref(addrs);
			}

		else if ( timeout )
			i->second->Timeout();

		else
			return;

		asyncs_names.erase(i);
		--asyncs_pending;

		// Don't delete the request.  That will be done once it
		// eventually times out.
		}
	}

void  DNS_Mgr::Process()
	{

	while ( asyncs_timeouts.size() > 0 )
		{
		AsyncRequest* req = asyncs_timeouts.top();

		if ( req->time + DNS_TIMEOUT > current_time() )
			break;

		if ( req->IsAddrReq() )
			CheckAsyncAddrRequest(req->host, true);
		else
			CheckAsyncHostRequest(req->name.c_str(), true);

		asyncs_timeouts.pop();
		delete req;
		}

	if ( asyncs_addrs.size() == 0 && asyncs_names.size() == 0 )
		return;

	if ( AnswerAvailable(0) <= 0 )
		return;

	char err[NB_DNS_ERRSIZE];
	struct nb_dns_result r;

	int status = nb_dns_activity(nb_dns, &r, err);

	if ( status < 0 )
		internal_error("NB-DNS error in DNS_Mgr::Process (%s)", err);

	else if ( status > 0 )
		{
		DNS_Mgr_Request* dr = (DNS_Mgr_Request*) r.cookie;
		if ( dr->RequestPending() )
			{
			AddResult(dr, &r);
			dr->RequestDone();
			}

		if ( ! dr->ReqHost() )
			CheckAsyncAddrRequest(dr->ReqAddr(), true);
		else
			CheckAsyncHostRequest(dr->ReqHost(), true);

		IssueAsyncRequests();
		}
	}

int DNS_Mgr::AnswerAvailable(int timeout)
	{
	int fd = nb_dns_fd(nb_dns);
	if ( fd < 0 )
		internal_error("nb_dns_fd() failed in DNS_Mgr::WaitForReplies");

	fd_set read_fds;

	FD_ZERO(&read_fds);
	FD_SET(fd, &read_fds);

	struct timeval t;
	t.tv_sec = timeout;
	t.tv_usec = 0;

	int status = select(fd+1, &read_fds, 0, 0, &t);

	if ( status < 0 )
		{
		if ( errno == EINTR )
			return -1;
		internal_error("problem with DNS select");
		}

	if ( status > 1 )
		internal_error("strange return from DNS select");

	return status;
	}
