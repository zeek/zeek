// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/DNS_Mgr.h"

#include "zeek/zeek-config.h"

#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <algorithm>
#include <vector>

#ifdef TIME_WITH_SYS_TIME
#include <sys/time.h>
#include <time.h>
#elif defined(HAVE_SYS_TIME_H)
#include <sys/time.h>
#else
#include <time.h>
#endif

#include <ares.h>
#include <ares_dns.h>

#include "zeek/3rdparty/doctest.h"
#include "zeek/DNS_Mapping.h"
#include "zeek/Event.h"
#include "zeek/Expr.h"
#include "zeek/Hash.h"
#include "zeek/ID.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/NetVar.h"
#include "zeek/Reporter.h"
#include "zeek/RunState.h"
#include "zeek/Val.h"
#include "zeek/ZeekString.h"
#include "zeek/iosource/Manager.h"

// Number of seconds we'll wait for a reply.
constexpr int DNS_TIMEOUT = 5;

namespace zeek::detail
	{

static void hostbyaddr_callback(void* arg, int status, int timeouts, struct hostent* hostent)
	{
	printf("host callback\n");
	// TODO: implement this
	// TODO: figure out how to get TTL info here
	}

static void addrinfo_callback(void* arg, int status, int timeouts, struct ares_addrinfo* result)
	{
	printf("addrinfo callback\n");

	if ( status != ARES_SUCCESS )
		{
		// TODO: error or something here, or just give up on it?
		ares_freeaddrinfo(result);
		return;
		}

	// TODO: the existing code doesn't handle hostname aliases at all. Should we?
	// TODO: handle IPv6 mode

	std::vector<in_addr*> addrs;
	for ( ares_addrinfo_node* entry = result->nodes; entry != NULL; entry = entry->ai_next )
		addrs.push_back(&reinterpret_cast<sockaddr_in*>(entry->ai_addr)->sin_addr);

	// Push a null on the end so the addr list has a final point during later parsing.
	addrs.push_back(NULL);

	struct hostent he;
	he.h_name = util::copy_string(result->name);
	he.h_aliases = NULL;
	he.h_addrtype = AF_INET;
	he.h_length = sizeof(in_addr);
	he.h_addr_list = reinterpret_cast<char**>(addrs.data());

	auto req = reinterpret_cast<DNS_Mgr_Request*>(arg);
	dns_mgr->AddResult(req, &he, result->nodes[0].ai_ttl);

	delete[] he.h_name;

	ares_freeaddrinfo(result);
	}

static void ares_sock_cb(void* data, int s, int read, int write)
	{
	printf("Change state fd %d read:%d write:%d\n", s, read, write);
	if ( read == 1 )
		iosource_mgr->RegisterFd(s, reinterpret_cast<DNS_Mgr*>(data));
	else
		iosource_mgr->UnregisterFd(s, reinterpret_cast<DNS_Mgr*>(data));
	}

class DNS_Mgr_Request
	{
public:
	DNS_Mgr_Request(const char* h, int af, bool is_txt)
		: host(util::copy_string(h)), fam(af), qtype(is_txt ? 16 : 0), addr()
		{
		}

	DNS_Mgr_Request(const IPAddr& a) : addr(a) { }

	~DNS_Mgr_Request() { delete[] host; }

	// Returns nil if this was an address request.
	const char* ReqHost() const { return host; }
	const IPAddr& ReqAddr() const { return addr; }
	int Family() const { return fam; }
	bool ReqIsTxt() const { return qtype == 16; }

	void MakeRequest(ares_channel channel);

	bool RequestPending() const { return request_pending; }
	void RequestDone() { request_pending = false; }

protected:
	char* host = nullptr; // if non-nil, this is a host request
	int fam = 0; // address family query type for host requests
	int qtype = 0; // Query type
	IPAddr addr;
	bool request_pending = false;
	};

void DNS_Mgr_Request::MakeRequest(ares_channel channel)
	{
	request_pending = true;

	// TODO: TXT requests?
	// TODO: could this use ares_create_query/ares_query instead of the
	// ares_get* methods to make it more generic? I think we might need
	// to do that for TXT requests.

	if ( host )
		{
		ares_addrinfo_hints hints = {ARES_AI_CANONNAME, fam, 0, 0};
		ares_getaddrinfo(channel, host, NULL, &hints, addrinfo_callback, this);
		}
	else
		{
		const uint32_t* bytes;
		int len = addr.GetBytes(&bytes);

		ares_gethostbyaddr(channel, bytes, len, addr.GetFamily() == IPv4 ? AF_INET : AF_INET6,
		                   hostbyaddr_callback, this);
		}
	}

DNS_Mgr::DNS_Mgr(DNS_MgrMode arg_mode)
	{
	did_init = false;

	mode = arg_mode;

	asyncs_pending = 0;
	num_requests = 0;
	successful = 0;
	failed = 0;
	ipv6_resolver = false;

	ares_library_init(ARES_LIB_INIT_ALL);
	}

DNS_Mgr::~DNS_Mgr()
	{
	Flush();

	ares_cancel(channel);
	ares_destroy(channel);
	ares_library_cleanup();
	}

void DNS_Mgr::InitSource()
	{
	if ( did_init )
		return;

	ares_options options;
	int optmask = 0;

	options.flags = ARES_FLAG_STAYOPEN;
	optmask |= ARES_OPT_FLAGS;

	options.timeout = DNS_TIMEOUT;
	optmask |= ARES_OPT_TIMEOUT;

	options.sock_state_cb = ares_sock_cb;
	options.sock_state_cb_data = this;
	optmask |= ARES_OPT_SOCK_STATE_CB;

	int status = ares_init_options(&channel, &options, optmask);
	if ( status != ARES_SUCCESS )
		reporter->FatalError("Failed to initialize c-ares for DNS resolution: %s",
		                     ares_strerror(status));

	// Note that Init() may be called by way of LookupHost() during the act of
	// parsing a hostname literal (e.g. google.com), so we can't use a
	// script-layer option to configure the DNS resolver as it may not be
	// configured to the user's desired address at the time when we need to to
	// the lookup.
	auto dns_resolver = getenv("ZEEK_DNS_RESOLVER");
	if ( dns_resolver )
		{
		ares_addr_node servers;
		servers.next = nullptr;

		auto dns_resolver_addr = IPAddr(dns_resolver);
		struct sockaddr_storage ss = {0};

		if ( dns_resolver_addr.GetFamily() == IPv4 )
			{
			struct sockaddr_in* sa = (struct sockaddr_in*)&ss;
			sa->sin_family = AF_INET;
			dns_resolver_addr.CopyIPv4(&sa->sin_addr);

			servers.family = AF_INET;
			memcpy(&(servers.addr.addr4), &sa->sin_addr, sizeof(struct in_addr));
			}
		else
			{
			struct sockaddr_in6* sa = (struct sockaddr_in6*)&ss;
			sa->sin6_family = AF_INET6;
			dns_resolver_addr.CopyIPv6(&sa->sin6_addr);

			servers.family = AF_INET6;
			memcpy(&(servers.addr.addr6), &sa->sin6_addr, sizeof(ares_in6_addr));
			}

		ares_set_servers(channel, &servers);
		}

	did_init = true;
	}

void DNS_Mgr::InitPostScript()
	{
	if ( ! doctest::is_running_in_test )
		{
		dm_rec = id::find_type<RecordType>("dns_mapping");

		// Registering will call InitSource(), which sets up all of the DNS library stuff
		iosource_mgr->Register(this, true);
		}
	else
		{
		// This would normally be called when registering the iosource above.
		InitSource();
		}

	// Load the DNS cache from disk, if it exists.
	std::string cache_dir = dir.empty() ? dir : ".";
	cache_name = util::fmt("%s/%s", cache_dir.c_str(), ".zeek-dns-cache");
	LoadCache(cache_name);
	}

static TableValPtr fake_name_lookup_result(const char* name)
	{
	hash128_t hash;
	KeyedHash::StaticHash128(name, strlen(name), &hash);
	auto hv = make_intrusive<ListVal>(TYPE_ADDR);
	hv->Append(make_intrusive<AddrVal>(reinterpret_cast<const uint32_t*>(&hash)));
	return hv->ToSetVal();
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
	snprintf(tmp, sizeof(tmp), "fake_addr_lookup_result_%s", addr.AsString().c_str());
	return tmp;
	}

TableValPtr DNS_Mgr::LookupHost(const char* name)
	{
	if ( mode == DNS_FAKE )
		return fake_name_lookup_result(name);

	// This should have been run already from InitPostScript(), but just run it again just
	// in case it hadn't.
	InitSource();

	// Check the cache before attempting to look up the name remotely.
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
				auto tv4 = d4->AddrsSet();
				auto tv6 = d6->AddrsSet();
				tv4->AddTo(tv6.get(), false);
				return tv6;
				}
			}
		}

	// Not found, or priming. We use ares_getaddrinfo here because we want the TTL value
	switch ( mode )
		{
		case DNS_PRIME:
			{
			// TODO: not sure we need to do these split like this if we can pass AF_UNSPEC
			// in the hints structure. Do we really need the two different request objects?
			auto v4 = new DNS_Mgr_Request(name, AF_INET, false);
			ares_addrinfo_hints v4_hints = {ARES_AI_CANONNAME, AF_INET, 0, 0};
			ares_getaddrinfo(channel, name, NULL, &v4_hints, addrinfo_callback, v4);

			// TODO: check if ipv6 support is needed if we use AF_UNSPEC above
			// auto v6 = new DNS_Mgr_Request(name, AF_INET6, false);
			// ares_addrinfo_hints v6_hints = { 0, AF_INET6, 0, 0 };
			// ares_getaddrinfo(channel, name, NULL, &v6_hints, addrinfo_callback, v6);

			return empty_addr_set();
			}

		case DNS_FORCE:
			reporter->FatalError("can't find DNS entry for %s in cache", name);
			return nullptr;

		case DNS_DEFAULT:
			{
			auto v4 = new DNS_Mgr_Request(name, AF_INET, false);
			ares_addrinfo_hints v4_hints = {ARES_AI_CANONNAME, AF_INET, 0, 0};
			ares_getaddrinfo(channel, name, NULL, &v4_hints, addrinfo_callback, v4);

			// TODO: check if ipv6 support is needed if we use AF_UNSPEC above
			// auto v6 = new DNS_Mgr_Request(name, AF_INET6, false);
			// ares_addrinfo_hints v6_hints = { 0, AF_INET6, 0, 0 };
			// ares_getaddrinfo(channel, name, NULL, &v6_hints, addrinfo_callback, v6);

			Resolve();

			// Call LookupHost() a second time to get the newly stored value out of the cache.
			return LookupHost(name);
			}

		default:
			reporter->InternalError("bad mode in DNS_Mgr::LookupHost");
			return nullptr;
		}
	}

StringValPtr DNS_Mgr::LookupAddr(const IPAddr& addr)
	{
	if ( mode == DNS_FAKE )
		return make_intrusive<StringVal>(fake_addr_lookup_result(addr));

	// This should have been run already from InitPostScript(), but just run it again just
	// in case it hadn't.
	InitSource();

	// Check the cache before attempting to look up the name remotely.
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
				std::string s(addr);
				reporter->Warning("can't resolve IP address: %s", s.c_str());
				return make_intrusive<StringVal>(s.c_str());
				}
			}
		}

	const uint32_t* bytes;
	int len = addr.GetBytes(&bytes);

	// Not found, or priming.
	switch ( mode )
		{
		case DNS_PRIME:
			{
			auto req = new DNS_Mgr_Request(addr);
			ares_gethostbyaddr(channel, bytes, len, addr.GetFamily() == IPv4 ? AF_INET : AF_INET6,
			                   hostbyaddr_callback, req);
			return make_intrusive<StringVal>("<none>");
			}

		case DNS_FORCE:
			reporter->FatalError("can't find DNS entry for %s in cache", addr.AsString().c_str());
			return nullptr;

		case DNS_DEFAULT:
			{
			auto req = new DNS_Mgr_Request(addr);
			ares_gethostbyaddr(channel, bytes, len, addr.GetFamily() == IPv4 ? AF_INET : AF_INET6,
			                   hostbyaddr_callback, req);
			Resolve();

			// Call LookupAddr() a second time to get the newly stored value out of the cache.
			return LookupAddr(addr);
			}

		default:
			reporter->InternalError("bad mode in DNS_Mgr::LookupAddr");
			return nullptr;
		}
	}

constexpr int MAX_PENDING_REQUESTS = 20;

void DNS_Mgr::Resolve()
	{
	int nfds = 0;
	struct timeval *tvp, tv;
	fd_set read_fds, write_fds;

	tv.tv_sec = DNS_TIMEOUT;
	tv.tv_usec = 0;

	for ( int i = 0; i < MAX_PENDING_REQUESTS; i++ )
		{
		FD_ZERO(&read_fds);
		FD_ZERO(&write_fds);
		nfds = ares_fds(channel, &read_fds, &write_fds);
		if ( nfds == 0 )
			break;

		tvp = ares_timeout(channel, &tv, &tv);
		select(nfds, &read_fds, &write_fds, NULL, tvp);
		ares_process(channel, &read_fds, &write_fds);
		}
	}

void DNS_Mgr::Event(EventHandlerPtr e, DNS_Mapping* dm)
	{
	if ( ! e )
		return;
	event_mgr.Enqueue(e, BuildMappingVal(dm));
	}

void DNS_Mgr::Event(EventHandlerPtr e, DNS_Mapping* dm, ListValPtr l1, ListValPtr l2)
	{
	if ( ! e )
		return;

	event_mgr.Enqueue(e, BuildMappingVal(dm), l1->ToSetVal(), l2->ToSetVal());
	}

void DNS_Mgr::Event(EventHandlerPtr e, DNS_Mapping* old_dm, DNS_Mapping* new_dm)
	{
	if ( ! e )
		return;

	event_mgr.Enqueue(e, BuildMappingVal(old_dm), BuildMappingVal(new_dm));
	}

ValPtr DNS_Mgr::BuildMappingVal(DNS_Mapping* dm)
	{
	if ( ! dm_rec )
		return nullptr;

	auto r = make_intrusive<RecordVal>(dm_rec);

	r->AssignTime(0, dm->CreationTime());
	r->Assign(1, dm->ReqHost() ? dm->ReqHost() : "");
	r->Assign(2, make_intrusive<AddrVal>(dm->ReqAddr()));
	r->Assign(3, dm->Valid());

	auto h = dm->Host();
	r->Assign(4, h ? std::move(h) : make_intrusive<StringVal>("<none>"));
	r->Assign(5, dm->AddrsSet());

	return r;
	}

void DNS_Mgr::AddResult(DNS_Mgr_Request* dr, struct hostent* h, uint32_t ttl)
	{
	DNS_Mapping* new_dm;
	DNS_Mapping* prev_dm;
	bool keep_prev = false;

	if ( dr->ReqHost() )
		{
		new_dm = new DNS_Mapping(dr->ReqHost(), h, ttl);
		prev_dm = nullptr;

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
				keep_prev = true;
				}
			}
		else
			{
			HostMap::iterator it = host_mappings.find(dr->ReqHost());
			if ( it == host_mappings.end() )
				{
				host_mappings[dr->ReqHost()].first = new_dm->Type() == AF_INET ? new_dm : nullptr;

				host_mappings[dr->ReqHost()].second = new_dm->Type() == AF_INET ? nullptr : new_dm;
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

				keep_prev = true;
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
			keep_prev = true;
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

	auto prev_s = prev_dm->Host();
	auto new_s = new_dm->Host();

	if ( prev_s || new_s )
		{
		if ( ! prev_s )
			Event(dns_mapping_new_name, new_dm);
		else if ( ! new_s )
			Event(dns_mapping_lost_name, prev_dm);
		else if ( ! Bstr_eq(new_s->AsString(), prev_s->AsString()) )
			Event(dns_mapping_name_changed, prev_dm, new_dm);
		}

	auto prev_a = prev_dm->Addrs();
	auto new_a = new_dm->Addrs();

	if ( ! prev_a || ! new_a )
		{
		reporter->InternalWarning("confused in DNS_Mgr::CompareMappings");
		return;
		}

	auto prev_delta = AddrListDelta(prev_a.get(), new_a.get());
	auto new_delta = AddrListDelta(new_a.get(), prev_a.get());

	if ( prev_delta->Length() > 0 || new_delta->Length() > 0 )
		Event(dns_mapping_altered, new_dm, std::move(prev_delta), std::move(new_delta));
	}

ListValPtr DNS_Mgr::AddrListDelta(ListVal* al1, ListVal* al2)
	{
	auto delta = make_intrusive<ListVal>(TYPE_ADDR);

	for ( int i = 0; i < al1->Length(); ++i )
		{
		const IPAddr& al1_i = al1->Idx(i)->AsAddr();

		int j;
		for ( j = 0; j < al2->Length(); ++j )
			{
			const IPAddr& al2_j = al2->Idx(j)->AsAddr();
			if ( al1_i == al2_j )
				break;
			}

		if ( j >= al2->Length() )
			// Didn't find it.
			delta->Append(al1->Idx(i));
		}

	return delta;
	}

void DNS_Mgr::DumpAddrList(FILE* f, ListVal* al)
	{
	for ( int i = 0; i < al->Length(); ++i )
		{
		const IPAddr& al_i = al->Idx(i)->AsAddr();
		fprintf(f, "%s%s", i > 0 ? "," : "", al_i.AsString().c_str());
		}
	}

void DNS_Mgr::LoadCache(const std::string& path)
	{
	FILE* f = fopen(path.c_str(), "r");

	if ( ! f )
		return;

	// Loop until we find a mapping that doesn't initialize correctly.
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

bool DNS_Mgr::Save()
	{
	if ( cache_name.empty() )
		return false;

	FILE* f = fopen(cache_name.c_str(), "w");

	if ( ! f )
		return false;

	Save(f, host_mappings);
	Save(f, addr_mappings);
	// Save(f, text_mappings); // We don't save the TXT mappings (yet?).

	fclose(f);

	return true;
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
	for ( HostMap::const_iterator it = m.begin(); it != m.end(); ++it )
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
		return nullptr;

	DNS_Mapping* d = it->second;

	if ( d->Expired() )
		{
		addr_mappings.erase(it);
		delete d;
		return nullptr;
		}

	// The escapes in the following strings are to avoid having it
	// interpreted as a trigraph sequence.
	return d->names.empty() ? "<\?\?\?>" : d->names[0].c_str();
	}

TableValPtr DNS_Mgr::LookupNameInCache(const std::string& name)
	{
	HostMap::iterator it = host_mappings.find(name);
	if ( it == host_mappings.end() )
		{
		it = host_mappings.begin();
		return nullptr;
		}

	DNS_Mapping* d4 = it->second.first;
	DNS_Mapping* d6 = it->second.second;

	if ( ! d4 || d4->names.empty() || ! d6 || d6->names.empty() )
		return nullptr;

	if ( d4->Expired() || d6->Expired() )
		{
		host_mappings.erase(it);
		delete d4;
		delete d6;
		return nullptr;
		}

	auto tv4 = d4->AddrsSet();
	auto tv6 = d6->AddrsSet();
	tv4->AddTo(tv6.get(), false);
	return tv6;
	}

const char* DNS_Mgr::LookupTextInCache(const std::string& name)
	{
	TextMap::iterator it = text_mappings.find(name);
	if ( it == text_mappings.end() )
		return nullptr;

	DNS_Mapping* d = it->second;

	if ( d->Expired() )
		{
		text_mappings.erase(it);
		delete d;
		return nullptr;
		}

	// The escapes in the following strings are to avoid having it
	// interpreted as a trigraph sequence.
	return d->names.empty() ? "<\?\?\?>" : d->names[0].c_str();
	}

static void resolve_lookup_cb(DNS_Mgr::LookupCallback* callback, TableValPtr result)
	{
	callback->Resolved(result.get());

	// Don't delete this if testing because we need it to look at the results of the
	// request. It'll get deleted by the test when finished.
	if ( ! doctest::is_running_in_test )
		delete callback;
	}

static void resolve_lookup_cb(DNS_Mgr::LookupCallback* callback, const char* result)
	{
	callback->Resolved(result);

	// Don't delete this if testing because we need it to look at the results of the
	// request. It'll get deleted by the test when finished.
	if ( ! doctest::is_running_in_test )
		delete callback;
	}

void DNS_Mgr::AsyncLookupAddr(const IPAddr& host, LookupCallback* callback)
	{
	// This should have been run already from InitPostScript(), but just run it again just
	// in case it hadn't.
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

	AsyncRequest* req = nullptr;

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

void DNS_Mgr::AsyncLookupName(const std::string& name, LookupCallback* callback)
	{
	// This should have been run already from InitPostScript(), but just run it again just
	// in case it hadn't.
	InitSource();

	if ( mode == DNS_FAKE )
		{
		resolve_lookup_cb(callback, fake_name_lookup_result(name.c_str()));
		return;
		}

	// Do we already know the answer?
	auto addrs = LookupNameInCache(name);
	if ( addrs )
		{
		resolve_lookup_cb(callback, std::move(addrs));
		return;
		}

	AsyncRequest* req = nullptr;

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

void DNS_Mgr::AsyncLookupNameText(const std::string& name, LookupCallback* callback)
	{
	// This should have been run already from InitPostScript(), but just run it again just
	// in case it hadn't.
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

	AsyncRequest* req = nullptr;

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

void DNS_Mgr::IssueAsyncRequests()
	{
	while ( ! asyncs_queued.empty() && asyncs_pending < MAX_PENDING_REQUESTS )
		{
		AsyncRequest* req = asyncs_queued.front();
		asyncs_queued.pop_front();

		++num_requests;
		req->time = util::current_time();

		if ( req->IsAddrReq() )
			{
			auto* m_req = new DNS_Mgr_Request(req->host);
			m_req->MakeRequest(channel);
			}
		else if ( req->is_txt )
			{
			auto* m_req = new DNS_Mgr_Request(req->name.c_str(), AF_INET, req->is_txt);
			m_req->MakeRequest(channel);
			}
		else
			{
			// If only one request type succeeds, don't consider it a failure.
			auto* m_req4 = new DNS_Mgr_Request(req->name.c_str(), AF_INET, req->is_txt);
			m_req4->MakeRequest(channel);
			auto* m_req6 = new DNS_Mgr_Request(req->name.c_str(), AF_INET6, req->is_txt);
			m_req6->MakeRequest(channel);
			}

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
		auto addrs = LookupNameInCache(host);

		if ( addrs )
			{
			++successful;
			i->second->Resolved(addrs.get());
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

	return run_state::network_time + DNS_TIMEOUT;
	}

void DNS_Mgr::Process()
	{
	while ( ! asyncs_timeouts.empty() )
		{
		AsyncRequest* req = asyncs_timeouts.top();

		if ( req->time + DNS_TIMEOUT > util::current_time() && ! run_state::terminating )
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

	Resolve();

	// TODO: what does the rest below do?
	/*
	char err[NB_DNS_ERRSIZE];
	struct nb_dns_result r;

	int status = nb_dns_activity(nb_dns, &r, err);

	if ( status < 0 )
	    reporter->Warning("NB-DNS error in DNS_Mgr::Process (%s)", err);

	else if ( status > 0 )
	    {
	    DNS_Mgr_Request* dr = (DNS_Mgr_Request*)r.cookie;

	    bool do_host_timeout = true;
	    if ( dr->ReqHost() && host_mappings.find(dr->ReqHost()) == host_mappings.end() )
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
	*/
	}

void DNS_Mgr::GetStats(Stats* stats)
	{
	// TODO: can this use the telemetry framework?
	stats->requests = num_requests;
	stats->successful = successful;
	stats->failed = failed;
	stats->pending = asyncs_pending;
	stats->cached_hosts = host_mappings.size();
	stats->cached_addresses = addr_mappings.size();
	stats->cached_texts = text_mappings.size();
	}

void DNS_Mgr::TestProcess()
	{
	// Only allow usage of this method when running unit tests.
	assert(doctest::is_running_in_test);
	Process();
	}

void DNS_Mgr::AsyncRequest::Resolved(const char* name)
	{
	for ( const auto& cb : callbacks )
		{
		cb->Resolved(name);
		if ( ! doctest::is_running_in_test )
			delete cb;
		}

	callbacks.clear();
	processed = true;
	}

void DNS_Mgr::AsyncRequest::Resolved(TableVal* addrs)
	{
	for ( const auto& cb : callbacks )
		{
		cb->Resolved(addrs);
		if ( ! doctest::is_running_in_test )
			delete cb;
		}

	callbacks.clear();
	processed = true;
	}

void DNS_Mgr::AsyncRequest::Timeout()
	{
	for ( const auto& cb : callbacks )
		{
		cb->Timeout();
		if ( ! doctest::is_running_in_test )
			delete cb;
		}

	callbacks.clear();
	processed = true;
	}

TableValPtr DNS_Mgr::empty_addr_set()
	{
	// TODO: can this be returned statically as well? Does the result get used in a way
	// that would modify the same value being returned repeatedly?
	auto addr_t = base_type(TYPE_ADDR);
	auto set_index = make_intrusive<TypeList>(addr_t);
	set_index->Append(std::move(addr_t));
	auto s = make_intrusive<SetType>(std::move(set_index), nullptr);
	return make_intrusive<TableVal>(std::move(s));
	}

//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////

static std::vector<IPAddr> get_result_addresses(TableVal* addrs)
	{
	std::vector<IPAddr> results;

	auto m = addrs->ToMap();
	for ( const auto& [k, v] : m )
		{
		auto lv = cast_intrusive<ListVal>(k);
		auto lvv = lv->Vals();
		for ( const auto& addr : lvv )
			{
			auto addr_ptr = cast_intrusive<AddrVal>(addr);
			results.push_back(addr_ptr->Get());
			}
		}

	return results;
	}

class TestCallback : public DNS_Mgr::LookupCallback
	{
public:
	TestCallback() { }
	void Resolved(const char* name) override
		{
		host_result = name;
		done = true;
		}
	void Resolved(TableVal* addrs) override
		{
		addr_results = get_result_addresses(addrs);
		done = true;
		}
	void Timeout() override
		{
		timeout = true;
		done = true;
		}

	std::string host_result;
	std::vector<IPAddr> addr_results;
	bool done = false;
	bool timeout = false;
	};

TEST_CASE("dns_mgr prime,save,load")
	{
	char prefix[] = "/tmp/zeek-unit-test-XXXXXX";
	auto tmpdir = mkdtemp(prefix);

	// Create a manager to prime the cache, make a few requests, and the save
	// the result. This tests that the priming code will create the requests but
	// wait for Resolve() to actually make the requests.
	DNS_Mgr mgr(DNS_PRIME);
	mgr.SetDir(tmpdir);
	mgr.InitPostScript();

	auto host_result = mgr.LookupHost("one.one.one.one");
	REQUIRE(host_result != nullptr);
	CHECK(host_result->EqualTo(DNS_Mgr::empty_addr_set()));

	IPAddr ones("1.1.1.1");
	auto addr_result = mgr.LookupAddr(ones);
	CHECK(strcmp(addr_result->CheckString(), "<none>") == 0);

	mgr.Resolve();

	// Save off the resulting values from Resolve() into a file on disk
	// in the tmpdir created by mkdtemp.
	REQUIRE(mgr.Save());

	// Make a second DNS manager and reload the cache that we just saved.
	DNS_Mgr mgr2(DNS_FORCE);
	mgr2.SetDir(tmpdir);
	mgr2.InitPostScript();

	// Make the same two requests, but verify that we're correctly getting
	// data out of the cache.
	host_result = mgr2.LookupHost("one.one.one.one");
	REQUIRE(host_result != nullptr);
	CHECK_FALSE(host_result->EqualTo(DNS_Mgr::empty_addr_set()));

	addr_result = mgr2.LookupAddr(ones);
	REQUIRE(addr_result != nullptr);
	CHECK(strcmp(addr_result->CheckString(), "one.one.one.one") == 0);
	}

TEST_CASE("dns_mgr alternate server")
	{
	char* old_server = getenv("ZEEK_DNS_RESOLVER");

	setenv("ZEEK_DNS_RESOLVER", "1.1.1.1", 1);
	DNS_Mgr mgr(DNS_DEFAULT);
	mgr.InitPostScript();

	auto result = mgr.LookupAddr("1.1.1.1");
	REQUIRE(result != nullptr);
	CHECK(strcmp(result->CheckString(), "one.one.one.one") == 0);

	// FIXME: This won't run on systems without IPv6 connectivity.
	// setenv("ZEEK_DNS_RESOLVER", "2606:4700:4700::1111", 1);
	// DNS_Mgr mgr2(DNS_DEFAULT, true);
	// mgr2.InitPostScript();
	// result = mgr2.LookupAddr("1.1.1.1");
	// mgr2.Resolve();

	// result = mgr2.LookupAddr("1.1.1.1");
	// CHECK(strcmp(result->CheckString(), "one.one.one.one") == 0);

	if ( old_server )
		setenv("ZEEK_DNS_RESOLVER", old_server, 1);
	else
		unsetenv("ZEEK_DNS_RESOLVER");
	}

TEST_CASE("dns_mgr default mode")
	{
	DNS_Mgr mgr(DNS_DEFAULT);
	mgr.InitPostScript();

	IPAddr ones("1.1.1.1");
	auto host_result = mgr.LookupHost("one.one.one.one");
	REQUIRE(host_result != nullptr);
	CHECK_FALSE(host_result->EqualTo(DNS_Mgr::empty_addr_set()));

	auto addrs_from_request = get_result_addresses(host_result.get());
	auto it = std::find(addrs_from_request.begin(), addrs_from_request.end(), ones);
	CHECK(it != addrs_from_request.end());

	auto addr_result = mgr.LookupAddr(ones);
	REQUIRE(addr_result != nullptr);
	CHECK(strcmp(addr_result->CheckString(), "one.one.one.one") == 0);

	IPAddr bad("240.0.0.0");
	addr_result = mgr.LookupAddr(bad);
	REQUIRE(addr_result != nullptr);
	CHECK(strcmp(addr_result->CheckString(), "240.0.0.0") == 0);
	}

TEST_CASE("dns_mgr async host")
	{
	DNS_Mgr mgr(DNS_DEFAULT);
	mgr.InitPostScript();

	TestCallback cb{};
	mgr.AsyncLookupName("one.one.one.one", &cb);

	// This shouldn't take any longer than DNS_TIMEOUT+1 seconds, so bound it
	// just in case of some failure we're not aware of yet.
	int count = 0;
	while ( ! cb.done && (count < DNS_TIMEOUT + 1) )
		{
		mgr.TestProcess();
		sleep(1);
		if ( ! cb.timeout )
			count++;
		}

	REQUIRE(count < (DNS_TIMEOUT + 1));
	if ( ! cb.timeout )
		{
		REQUIRE_FALSE(cb.addr_results.empty());
		IPAddr ones("1.1.1.1");
		auto it = std::find(cb.addr_results.begin(), cb.addr_results.end(), ones);
		CHECK(it != cb.addr_results.end());
		}

	mgr.Flush();
	}

TEST_CASE("dns_mgr async addr")
	{
	DNS_Mgr mgr(DNS_DEFAULT);
	mgr.InitPostScript();

	TestCallback cb{};
	mgr.AsyncLookupAddr(IPAddr{"1.1.1.1"}, &cb);

	// This shouldn't take any longer than DNS_TIMEOUT +1 seconds, so bound it
	// just in case of some failure we're not aware of yet.
	int count = 0;
	while ( ! cb.done && (count < DNS_TIMEOUT + 1) )
		{
		mgr.TestProcess();
		sleep(1);
		if ( ! cb.timeout )
			count++;
		}

	REQUIRE(count < (DNS_TIMEOUT + 1));
	if ( ! cb.timeout )
		REQUIRE(cb.host_result == "one.one.one.one");

	mgr.Flush();
	}

TEST_CASE("dns_mgr async text")
	{
	DNS_Mgr mgr(DNS_DEFAULT);
	mgr.InitPostScript();

	TestCallback cb{};
	mgr.AsyncLookupNameText("unittest.zeek.org", &cb);

	// This shouldn't take any longer than DNS_TIMEOUT +1 seconds, so bound it
	// just in case of some failure we're not aware of yet.
	int count = 0;
	while ( ! cb.done && (count < DNS_TIMEOUT + 1) )
		{
		mgr.TestProcess();
		sleep(1);
		if ( ! cb.timeout )
			count++;
		}

	REQUIRE(count < (DNS_TIMEOUT + 1));
	if ( ! cb.timeout )
		REQUIRE(cb.host_result == "testing dns_mgr");

	mgr.Flush();
	}

TEST_CASE("dns_mgr timeouts")
	{
	char* old_server = getenv("ZEEK_DNS_RESOLVER");

	// This is the address for blackhole.webpagetest.org, which provides a DNS
	// server that lets you connect but never returns any responses, always
	// resulting in a timeout.
	setenv("ZEEK_DNS_RESOLVER", "3.219.212.117", 1);
	DNS_Mgr mgr(DNS_DEFAULT);
	dns_mgr = &mgr;

	mgr.InitPostScript();
	auto addr_result = mgr.LookupAddr("1.1.1.1");
	REQUIRE(addr_result != nullptr);
	CHECK(strcmp(addr_result->CheckString(), "1.1.1.1") == 0);

	auto host_result = mgr.LookupHost("one.one.one.one");
	REQUIRE(host_result != nullptr);
	auto addresses = get_result_addresses(host_result.get());
	CHECK(addresses.size() == 0);

	if ( old_server )
		setenv("ZEEK_DNS_RESOLVER", old_server, 1);
	else
		unsetenv("ZEEK_DNS_RESOLVER");
	}

TEST_CASE("dns_mgr async timeouts")
	{
	char* old_server = getenv("ZEEK_DNS_RESOLVER");

	// This is the address for blackhole.webpagetest.org, which provides a DNS
	// server that lets you connect but never returns any responses, always
	// resulting in a timeout.
	setenv("ZEEK_DNS_RESOLVER", "3.219.212.117", 1);
	DNS_Mgr mgr(DNS_DEFAULT);
	dns_mgr = &mgr;
	mgr.InitPostScript();

	TestCallback cb{};
	mgr.AsyncLookupNameText("unittest.zeek.org", &cb);

	// This shouldn't take any longer than DNS_TIMEOUT +2 seconds, so bound it
	// just in case of some failure we're not aware of yet.
	int count = 0;
	while ( ! cb.done && (count < DNS_TIMEOUT + 1) )
		{
		mgr.TestProcess();
		sleep(1);
		if ( ! cb.timeout )
			count++;
		}

	REQUIRE(count < (DNS_TIMEOUT + 1));
	CHECK(cb.timeout);

	mgr.Flush();

	if ( old_server )
		setenv("ZEEK_DNS_RESOLVER", old_server, 1);
	else
		unsetenv("ZEEK_DNS_RESOLVER");
	}

	} // namespace zeek::detail
