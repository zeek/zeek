// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/DNS_Mgr.h"

#include "zeek/zeek-config.h"

#include <errno.h>
#include <netdb.h>
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
#include <ares_nameser.h>

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

// The maximum allowed number of pending asynchronous requests.
constexpr int MAX_PENDING_REQUESTS = 20;

namespace zeek::detail
	{

static void hostbyaddr_cb(void* arg, int status, int timeouts, struct hostent* hostent);
static void addrinfo_cb(void* arg, int status, int timeouts, struct ares_addrinfo* result);
static void query_cb(void* arg, int status, int timeouts, unsigned char* buf, int len);
static void sock_cb(void* data, int s, int read, int write);

class DNS_Request
	{
public:
	DNS_Request(std::string host, int af, int request_type, bool async = false);
	explicit DNS_Request(const IPAddr& addr, bool async = false);
	~DNS_Request();

	std::string Host() const { return host; }
	const IPAddr& Addr() const { return addr; }
	int Family() const { return family; }
	int RequestType() const { return request_type; }
	bool IsTxt() const { return request_type == 16; }

	void MakeRequest(ares_channel channel);
	void ProcessAsyncResult(bool timed_out);

private:
	std::string host;
	IPAddr addr;
	int family = 0; // address family query type for host requests
	int request_type = 0; // Query type
	bool async = false;
	unsigned char* query = nullptr;
	static uint16_t request_id;
	};

uint16_t DNS_Request::request_id = 0;

DNS_Request::DNS_Request(std::string host, int af, int request_type, bool async)
	: host(std::move(host)), family(af), request_type(request_type), async(async)
	{
	}

DNS_Request::DNS_Request(const IPAddr& addr, bool async) : addr(addr), async(async)
	{
	// TODO: AF_UNSPEC for T_PTR requests?
	family = addr.GetFamily() == IPv4 ? AF_INET : AF_INET6;
	request_type = T_PTR;
	}

DNS_Request::~DNS_Request()
	{
	if ( query )
		ares_free_string(query);
	}

void DNS_Request::MakeRequest(ares_channel channel)
	{
	// It's completely fine if this rolls over. It's just to keep the query ID different
	// from one query to the next, and it's unlikely we'd do 2^16 queries so fast that
	// all of them would be in flight at the same time.
	DNS_Request::request_id++;

	// TODO: how the heck do file lookups work? gethostbyname_file exists but gethostbyaddr_file
	// doesn't. But then the code in ares_gethostbyaddr.c can switch on the setting in the channel
	// for whether we should look at the file or not. If we don't care about file lookups at all,
	// the T_PTR case below can be simplified and moved down into the else block.

	// We do normal host and address lookups via the specialized methods for them
	// because those will attempt to do file lookups as well internally before
	// reaching out to the DNS server. The remaining lookup types all use
	// ares_create_query() and ares_send() for more genericness.
	if ( request_type == T_A || request_type == T_AAAA )
		{
		// TODO: gethostbyname_file?
		// Use getaddrinfo here because it gives us the ttl information. If we don't
		// care about TTL, we could use gethostbyname instead.
		ares_addrinfo_hints hints = {ARES_AI_CANONNAME, family, 0, 0};
		ares_getaddrinfo(channel, host.c_str(), NULL, &hints, addrinfo_cb, this);
		}
	else if ( request_type == T_PTR )
		{
		if ( addr.GetFamily() == IPv4 )
			{
			struct sockaddr_in sa;
			inet_pton(AF_INET, addr.AsString().c_str(), &(sa.sin_addr));
			ares_gethostbyaddr(channel, &sa.sin_addr, sizeof(sa.sin_addr), AF_INET, hostbyaddr_cb,
			                   this);
			}
		else
			{
			struct sockaddr_in6 sa;
			inet_pton(AF_INET6, addr.AsString().c_str(), &(sa.sin6_addr));
			ares_gethostbyaddr(channel, &sa.sin6_addr, sizeof(sa.sin6_addr), AF_INET6,
			                   hostbyaddr_cb, this);
			}
		}
	else
		{
		unsigned char* query = NULL;
		int len = 0;
		int status = ares_create_query(host.c_str(), C_IN, request_type, DNS_Request::request_id, 1,
		                               &query, &len, 0);
		if ( status != ARES_SUCCESS )
			return;

		// Store this so it can be destroyed when the request is destroyed.
		this->query = query;
		ares_send(channel, query, len, query_cb, this);
		}
	}

void DNS_Request::ProcessAsyncResult(bool timed_out)
	{
	if ( ! async )
		return;

	if ( request_type == T_A || request_type == T_AAAA )
		dns_mgr->CheckAsyncHostRequest(host, timed_out);
	else if ( request_type == T_PTR )
		dns_mgr->CheckAsyncAddrRequest(addr, timed_out);
	else if ( request_type == T_TXT )
		dns_mgr->CheckAsyncTextRequest(host, timed_out);
	}

/**
 * Called in response to ares_gethostbyaddr requests. Sends the hostent data to the
 * DNS manager via AddResult().
 */
static void hostbyaddr_cb(void* arg, int status, int timeouts, struct hostent* host)
	{
	auto req = reinterpret_cast<DNS_Request*>(arg);

	if ( ! host || status != ARES_SUCCESS )
		{
		printf("Failed hostbyaddr request: %s\n", ares_strerror(status));
		// TODO: pass DNS_TIMEOUT for the TTL here just so things work for testing. This
		// will absolutely need to get the data from the request somehow instead. See
		// https://github.com/c-ares/c-ares/issues/387.
		dns_mgr->AddResult(req, nullptr, DNS_TIMEOUT);
		}
	else
		{
		// TODO: pass DNS_TIMEOUT for the TTL here just so things work for testing. This
		// will absolutely need to get the data from the request somehow instead. See
		// https://github.com/c-ares/c-ares/issues/387.
		dns_mgr->AddResult(req, host, DNS_TIMEOUT);
		}

	req->ProcessAsyncResult(timeouts > 0);
	}

/**
 * Called in response to ares_getaddrinfo requests. Builds a hostent structure from
 * the result data and sends it to the DNS manager via Addresult().
 */
static void addrinfo_cb(void* arg, int status, int timeouts, struct ares_addrinfo* result)
	{
	auto req = reinterpret_cast<DNS_Request*>(arg);

	if ( status != ARES_SUCCESS )
		{
		// TODO: reporter warning or something here, or just give up on it?
		printf("Failed addrinfo request: %s", ares_strerror(status));
		dns_mgr->AddResult(req, nullptr, 0);
		}
	else
		{
		std::vector<in_addr*> addrs;
		std::vector<in6_addr*> addrs6;
		for ( ares_addrinfo_node* entry = result->nodes; entry != NULL; entry = entry->ai_next )
			{
			if ( entry->ai_family == AF_INET )
				{
				struct sockaddr_in* addr = reinterpret_cast<sockaddr_in*>(entry->ai_addr);
				addrs.push_back(&addr->sin_addr);
				}
			else if ( entry->ai_family == AF_INET6 )
				{
				struct sockaddr_in6* addr = (struct sockaddr_in6*)(entry->ai_addr);
				addrs6.push_back(&addr->sin6_addr);
				}
			}

		if ( ! addrs.empty() )
			{
			// Push a null on the end so the addr list has a final point during later parsing.
			addrs.push_back(NULL);

			struct hostent he;
			memset(&he, 0, sizeof(struct hostent));
			he.h_name = util::copy_string(result->name);
			he.h_addrtype = AF_INET;
			he.h_length = sizeof(in_addr);
			he.h_addr_list = reinterpret_cast<char**>(addrs.data());

			dns_mgr->AddResult(req, &he, result->nodes[0].ai_ttl);

			delete[] he.h_name;
			}

		// TODO: We can't do this here because we blow up the mapping added above by doing so.
		// We need some sort of "merge mapping" mode in AddResult for this to work to add new
		// IPs to an existing mapping.
		/*
		  if ( ! addrs6.empty() )
		  {
		  // Push a null on the end so the addr list has a final point during later parsing.
		  addrs6.push_back(NULL);

		  struct hostent he;
		  memset(&he, 0, sizeof(struct hostent));
		  he.h_name = util::copy_string(result->name);
		  he.h_addrtype = AF_INET6;
		  he.h_length = sizeof(in6_addr);
		  he.h_addr_list = reinterpret_cast<char**>(addrs6.data());

		  dns_mgr->AddResult(req, &he, result->nodes[0].ai_ttl);

		  delete[] he.h_name;
		  }
		*/
		}

	req->ProcessAsyncResult(timeouts > 0);

	ares_freeaddrinfo(result);
	}

/**
 * Called in response to all other query types.
 */
static void query_cb(void* arg, int status, int timeouts, unsigned char* buf, int len)
	{
	auto req = reinterpret_cast<DNS_Request*>(arg);

	if ( status != ARES_SUCCESS )
		{
		// TODO: reporter warning or something here, or just give up on it?
		// TODO: what should we send to AddResult if we didn't get an answer back?
		// struct hostent he;
		// memset(&he, 0, sizeof(struct hostent));
		// dns_mgr->AddResult(req, &he, 0);
		}
	else
		{
		switch ( req->RequestType() )
			{
			case T_TXT:
				{
				struct ares_txt_reply* reply;
				int r = ares_parse_txt_reply(buf, len, &reply);
				if ( r == ARES_SUCCESS )
					{
					// Use a hostent to send the data into AddResult(). We only care about
					// setting the host field, but everything else should be zero just for
					// safety.

					// We don't currently handle more than the first response, and throw the
					// rest away. There really isn't a good reason for this, we just haven't
					// ever done so. It would likely require some changes to the output from
					// Lookup(), since right now it only returns one value.
					struct hostent he;
					memset(&he, 0, sizeof(struct hostent));
					he.h_name = util::copy_string(reinterpret_cast<const char*>(reply->txt));

					// TODO: pass DNS_TIMEOUT for the TTL here just so things work for
					// testing. This will absolutely need to get the data from the request
					// somehow instead. See https://github.com/c-ares/c-ares/issues/387.
					dns_mgr->AddResult(req, &he, DNS_TIMEOUT);

					ares_free_data(reply);
					}

				break;
				}

			default:
				reporter->Error("Requests of type %d are unsupported", req->RequestType());
				break;
			}
		}

	req->ProcessAsyncResult(timeouts > 0);
	}

/**
 * Called when the c-ares socket changes state, whcih indicates that it's connected to
 * some source of data (either a host file or a DNS server). This indicates that we're
 * able to do lookups against c-ares now and should activate the IOSource.
 */
static void sock_cb(void* data, int s, int read, int write)
	{
	auto mgr = reinterpret_cast<DNS_Mgr*>(data);
	mgr->RegisterSocket(s, read == 1);
	}

DNS_Mgr::DNS_Mgr(DNS_MgrMode arg_mode) : mode(arg_mode)
	{
	ares_library_init(ARES_LIB_INIT_ALL);
	}

DNS_Mgr::~DNS_Mgr()
	{
	Flush();

	ares_cancel(channel);
	ares_destroy(channel);
	ares_library_cleanup();
	}

void DNS_Mgr::RegisterSocket(int fd, bool active)
	{
	if ( active && socket_fds.count(fd) == 0 )
		{
		socket_fds.insert(fd);
		iosource_mgr->RegisterFd(fd, this);
		}
	else if ( ! active && socket_fds.count(fd) != 0 )
		{
		socket_fds.erase(fd);
		iosource_mgr->UnregisterFd(fd, this);
		}
	}

void DNS_Mgr::InitSource()
	{
	if ( did_init )
		return;

	ares_options options;
	int optmask = 0;

	// Don't close the socket for the server even if we have no active
	// requests.
	options.flags = ARES_FLAG_STAYOPEN;
	optmask |= ARES_OPT_FLAGS;

	// This option is in milliseconds.
	options.timeout = DNS_TIMEOUT * 1000;
	optmask |= ARES_OPT_TIMEOUTMS;

	// This causes c-ares to only attempt each server twice before
	// giving up.
	options.tries = 2;
	optmask |= ARES_OPT_TRIES;

	// See the comment on sock_cb for how this gets used.
	options.sock_state_cb = sock_cb;
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
		servers.next = NULL;

		auto dns_resolver_addr = IPAddr(dns_resolver);
		struct sockaddr_storage ss = {0};

		if ( dns_resolver_addr.GetFamily() == IPv4 )
			{
			servers.family = AF_INET;
			dns_resolver_addr.CopyIPv4(&(servers.addr.addr4));
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
	std::string cache_dir = dir.empty() ? "." : dir;
	cache_name = util::fmt("%s/%s", cache_dir.c_str(), ".zeek-dns-cache");
	LoadCache(cache_name);
	}

static TableValPtr fake_name_lookup_result(const std::string& name)
	{
	hash128_t hash;
	KeyedHash::StaticHash128(name.c_str(), name.size(), &hash);
	auto hv = make_intrusive<ListVal>(TYPE_ADDR);
	hv->Append(make_intrusive<AddrVal>(reinterpret_cast<const uint32_t*>(&hash)));
	return hv->ToSetVal();
	}

static std::string fake_text_lookup_result(const std::string name)
	{
	return util::fmt("fake_text_lookup_result_%s", name.c_str());
	}

static std::string fake_addr_lookup_result(const IPAddr& addr)
	{
	return util::fmt("fake_addr_lookup_result_%s", addr.AsString().c_str());
	}

static void resolve_lookup_cb(DNS_Mgr::LookupCallback* callback, TableValPtr result)
	{
	callback->Resolved(std::move(result));
	delete callback;
	}

static void resolve_lookup_cb(DNS_Mgr::LookupCallback* callback, const std::string& result)
	{
	callback->Resolved(result);
	delete callback;
	}

ValPtr DNS_Mgr::Lookup(const std::string& name, int request_type)
	{
	if ( request_type == T_A || request_type == T_AAAA )
		return LookupHost(name);

	if ( mode == DNS_FAKE && request_type == T_TXT )
		return make_intrusive<StringVal>(fake_text_lookup_result(name));

	InitSource();

	if ( mode != DNS_PRIME && request_type == T_TXT )
		{
		if ( auto val = LookupTextInCache(name, false) )
			return val;
		}

	switch ( mode )
		{
		case DNS_PRIME:
			{
			auto req = new DNS_Request(name, AF_UNSPEC, request_type);
			req->MakeRequest(channel);
			return empty_addr_set();
			}

		case DNS_FORCE:
			reporter->FatalError("can't find DNS entry for %s (req type %d) in cache", name.c_str(),
			                     request_type);
			return nullptr;

		case DNS_DEFAULT:
			{
			auto req = new DNS_Request(name, AF_UNSPEC, request_type);
			req->MakeRequest(channel);
			Resolve();

			// Call LookupHost() a second time to get the newly stored value out of the cache.
			return Lookup(name, request_type);
			}

		default:
			reporter->InternalError("bad mode %d in DNS_Mgr::Lookup", mode);
			return nullptr;
		}

	return nullptr;
	}

TableValPtr DNS_Mgr::LookupHost(const std::string& name)
	{
	if ( mode == DNS_FAKE )
		return fake_name_lookup_result(name);

	InitSource();

	// Check the cache before attempting to look up the name remotely.
	if ( mode != DNS_PRIME )
		{
		if ( auto val = LookupNameInCache(name, false, true) )
			return val;
		}

	// Not found, or priming.
	switch ( mode )
		{
		case DNS_PRIME:
			{
			// We pass T_A here, but because we're passing AF_UNSPEC MakeRequest() will
			// have c-ares attempt to lookup both ipv4 and ipv6 at the same time.
			auto req = new DNS_Request(name, AF_UNSPEC, T_A);
			req->MakeRequest(channel);
			return empty_addr_set();
			}

		case DNS_FORCE:
			reporter->FatalError("can't find DNS entry for %s in cache", name.c_str());
			return nullptr;

		case DNS_DEFAULT:
			{
			// We pass T_A here, but because we're passing AF_UNSPEC MakeRequest() will
			// have c-ares attempt to lookup both ipv4 and ipv6 at the same time.
			auto req = new DNS_Request(name, AF_UNSPEC, T_A);
			req->MakeRequest(channel);
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

	InitSource();

	// Check the cache before attempting to look up the name remotely.
	if ( mode != DNS_PRIME )
		{
		if ( auto val = LookupAddrInCache(addr, false, true) )
			return val;
		}

	// Not found, or priming.
	switch ( mode )
		{
		case DNS_PRIME:
			{
			auto req = new DNS_Request(addr);
			req->MakeRequest(channel);
			return make_intrusive<StringVal>("<none>");
			}

		case DNS_FORCE:
			reporter->FatalError("can't find DNS entry for %s in cache", addr.AsString().c_str());
			return nullptr;

		case DNS_DEFAULT:
			{
			auto req = new DNS_Request(addr);
			req->MakeRequest(channel);
			Resolve();

			// Call LookupAddr() a second time to get the newly stored value out of the cache.
			return LookupAddr(addr);
			}

		default:
			reporter->InternalError("bad mode in DNS_Mgr::LookupAddr");
			return nullptr;
		}
	}

void DNS_Mgr::LookupHost(const std::string& name, LookupCallback* callback)
	{
	if ( mode == DNS_FAKE )
		{
		resolve_lookup_cb(callback, fake_name_lookup_result(name));
		return;
		}

	// Do we already know the answer?
	if ( auto addrs = LookupNameInCache(name, true, false) )
		{
		resolve_lookup_cb(callback, std::move(addrs));
		return;
		}

	AsyncRequest* req = nullptr;

	// If we already have a request waiting for this host, we don't need to make
	// another one. We can just add the callback to it and it'll get handled
	// when the first request comes back.
	AsyncRequestNameMap::iterator i = asyncs_names.find(name);
	if ( i != asyncs_names.end() )
		req = i->second;
	else
		{
		// A new one.
		req = new AsyncRequest{};
		req->host = name;
		asyncs_queued.push_back(req);
		asyncs_names.emplace_hint(i, name, req);
		}

	req->callbacks.push_back(callback);

	// There may be requests in the queue that haven't been processed yet
	// so go ahead and reissue them, even if this method didn't change
	// anything.
	IssueAsyncRequests();
	}

void DNS_Mgr::LookupAddr(const IPAddr& host, LookupCallback* callback)
	{
	if ( mode == DNS_FAKE )
		{
		resolve_lookup_cb(callback, fake_addr_lookup_result(host));
		return;
		}

	// Do we already know the answer?
	if ( auto name = LookupAddrInCache(host, true, false) )
		{
		resolve_lookup_cb(callback, name->CheckString());
		return;
		}

	AsyncRequest* req = nullptr;

	// If we already have a request waiting for this host, we don't need to make
	// another one. We can just add the callback to it and it'll get handled
	// when the first request comes back.
	AsyncRequestAddrMap::iterator i = asyncs_addrs.find(host);
	if ( i != asyncs_addrs.end() )
		req = i->second;
	else
		{
		// A new one.
		req = new AsyncRequest{};
		req->addr = host;
		asyncs_queued.push_back(req);
		asyncs_addrs.emplace_hint(i, host, req);
		}

	req->callbacks.push_back(callback);

	// There may be requests in the queue that haven't been processed yet
	// so go ahead and reissue them, even if this method didn't change
	// anything.
	IssueAsyncRequests();
	}

void DNS_Mgr::Lookup(const std::string& name, int request_type, LookupCallback* callback)
	{
	if ( request_type == T_A || request_type == T_AAAA )
		{
		LookupHost(name, callback);
		return;
		}

	if ( mode == DNS_FAKE )
		{
		resolve_lookup_cb(callback, fake_text_lookup_result(name));
		return;
		}

	// Do we already know the answer?
	if ( auto txt = LookupTextInCache(name, true) )
		{
		resolve_lookup_cb(callback, txt->CheckString());
		return;
		}

	AsyncRequest* req = nullptr;

	// If we already have a request waiting for this host, we don't need to make
	// another one. We can just add the callback to it and it'll get handled
	// when the first request comes back.
	AsyncRequestTextMap::iterator i = asyncs_texts.find(name);
	if ( i != asyncs_texts.end() )
		req = i->second;
	else
		{
		// A new one.
		req = new AsyncRequest{};
		req->host = name;
		req->is_txt = true;
		asyncs_queued.push_back(req);
		asyncs_texts.emplace_hint(i, name, req);
		}

	req->callbacks.push_back(callback);

	IssueAsyncRequests();
	}

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
	if ( e )
		event_mgr.Enqueue(e, BuildMappingVal(dm));
	}

void DNS_Mgr::Event(EventHandlerPtr e, DNS_Mapping* dm, ListValPtr l1, ListValPtr l2)
	{
	if ( e )
		event_mgr.Enqueue(e, BuildMappingVal(dm), l1->ToSetVal(), l2->ToSetVal());
	}

void DNS_Mgr::Event(EventHandlerPtr e, DNS_Mapping* old_dm, DNS_Mapping* new_dm)
	{
	if ( e )
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

void DNS_Mgr::AddResult(DNS_Request* dr, struct hostent* h, uint32_t ttl)
	{
	// TODO: the existing code doesn't handle hostname aliases at all. Should we?

	DNS_Mapping* new_mapping;
	DNS_Mapping* prev_mapping;
	bool keep_prev = false;

	if ( ! dr->Host().empty() )
		{
		new_mapping = new DNS_Mapping(dr->Host(), h, ttl);
		prev_mapping = nullptr;

		if ( dr->IsTxt() )
			{
			TextMap::iterator it = text_mappings.find(dr->Host());

			if ( it == text_mappings.end() )
				text_mappings[dr->Host()] = new_mapping;
			else
				{
				prev_mapping = it->second;
				it->second = new_mapping;
				}

			if ( new_mapping->Failed() && prev_mapping && prev_mapping->Valid() )
				{
				text_mappings[dr->Host()] = prev_mapping;
				keep_prev = true;
				}
			}
		else
			{
			HostMap::iterator it = host_mappings.find(dr->Host());
			if ( it == host_mappings.end() )
				{
				host_mappings[dr->Host()].first = new_mapping->Type() == AF_INET ? new_mapping
				                                                                 : nullptr;

				host_mappings[dr->Host()].second = new_mapping->Type() == AF_INET ? nullptr
				                                                                  : new_mapping;
				}
			else
				{
				if ( new_mapping->Type() == AF_INET )
					{
					prev_mapping = it->second.first;
					it->second.first = new_mapping;
					}
				else
					{
					prev_mapping = it->second.second;
					it->second.second = new_mapping;
					}
				}

			if ( new_mapping->Failed() && prev_mapping && prev_mapping->Valid() )
				{
				// Put previous, valid entry back - CompareMappings
				// will generate a corresponding warning.
				if ( prev_mapping->Type() == AF_INET )
					host_mappings[dr->Host()].first = prev_mapping;
				else
					host_mappings[dr->Host()].second = prev_mapping;

				keep_prev = true;
				}
			}
		}
	else
		{
		new_mapping = new DNS_Mapping(dr->Addr(), h, ttl);
		AddrMap::iterator it = addr_mappings.find(dr->Addr());
		prev_mapping = (it == addr_mappings.end()) ? 0 : it->second;
		addr_mappings[dr->Addr()] = new_mapping;

		if ( new_mapping->Failed() && prev_mapping && prev_mapping->Valid() )
			{
			addr_mappings[dr->Addr()] = prev_mapping;
			keep_prev = true;
			}
		}

	if ( prev_mapping && ! dr->IsTxt() )
		CompareMappings(prev_mapping, new_mapping);

	if ( keep_prev )
		delete new_mapping;
	else
		delete prev_mapping;
	}

void DNS_Mgr::CompareMappings(DNS_Mapping* prev_mapping, DNS_Mapping* new_mapping)
	{
	if ( prev_mapping->Failed() )
		{
		if ( new_mapping->Failed() )
			// Nothing changed.
			return;

		Event(dns_mapping_valid, new_mapping);
		return;
		}

	else if ( new_mapping->Failed() )
		{
		Event(dns_mapping_unverified, prev_mapping);
		return;
		}

	auto prev_s = prev_mapping->Host();
	auto new_s = new_mapping->Host();

	if ( prev_s || new_s )
		{
		if ( ! prev_s )
			Event(dns_mapping_new_name, new_mapping);
		else if ( ! new_s )
			Event(dns_mapping_lost_name, prev_mapping);
		else if ( ! Bstr_eq(new_s->AsString(), prev_s->AsString()) )
			Event(dns_mapping_name_changed, prev_mapping, new_mapping);
		}

	auto prev_a = prev_mapping->Addrs();
	auto new_a = new_mapping->Addrs();

	if ( ! prev_a || ! new_a )
		{
		reporter->InternalWarning("confused in DNS_Mgr::CompareMappings");
		return;
		}

	auto prev_delta = AddrListDelta(prev_a.get(), new_a.get());
	auto new_delta = AddrListDelta(new_a.get(), prev_a.get());

	if ( prev_delta->Length() > 0 || new_delta->Length() > 0 )
		Event(dns_mapping_altered, new_mapping, std::move(prev_delta), std::move(new_delta));
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

TableValPtr DNS_Mgr::LookupNameInCache(const std::string& name, bool cleanup_expired,
                                       bool check_failed)
	{
	HostMap::iterator it = host_mappings.find(name);
	if ( it == host_mappings.end() )
		return nullptr;

	DNS_Mapping* d4 = it->second.first;
	DNS_Mapping* d6 = it->second.second;

	if ( (! d4 || d4->names.empty()) && (! d6 || d6->names.empty()) )
		return nullptr;

	if ( cleanup_expired && ((d4 && d4->Expired()) || (d6 && d6->Expired())) )
		{
		host_mappings.erase(it);
		delete d4;
		delete d6;
		return nullptr;
		}

	if ( check_failed && ((d4 && d4->Failed()) || (d6 && d6->Failed())) )
		{
		reporter->Warning("Can't resolve host: %s", name.c_str());
		return empty_addr_set();
		}

	auto tv4 = d4->AddrsSet();

	if ( d6 )
		{
		auto tv6 = d6->AddrsSet();
		tv4->AddTo(tv6.get(), false);
		return tv6;
		}

	return tv4;
	}

StringValPtr DNS_Mgr::LookupAddrInCache(const IPAddr& addr, bool cleanup_expired, bool check_failed)
	{
	AddrMap::iterator it = addr_mappings.find(addr);
	if ( it == addr_mappings.end() )
		return nullptr;

	DNS_Mapping* d = it->second;

	if ( cleanup_expired && d->Expired() )
		{
		addr_mappings.erase(it);
		delete d;
		return nullptr;
		}
	else if ( check_failed && d->Failed() )
		{
		std::string s(addr);
		reporter->Warning("can't resolve IP address: %s", s.c_str());
		return make_intrusive<StringVal>(s);
		}

	if ( d->Host() )
		return d->Host();

	return make_intrusive<StringVal>("<\?\?\?>");
	}

StringValPtr DNS_Mgr::LookupTextInCache(const std::string& name, bool cleanup_expired)
	{
	TextMap::iterator it = text_mappings.find(name);
	if ( it == text_mappings.end() )
		return nullptr;

	DNS_Mapping* d = it->second;

	if ( cleanup_expired && d->Expired() )
		{
		text_mappings.erase(it);
		delete d;
		return nullptr;
		}

	if ( d->Host() )
		return d->Host();

	return make_intrusive<StringVal>("<\?\?\?>");
	}

void DNS_Mgr::IssueAsyncRequests()
	{
	while ( ! asyncs_queued.empty() && asyncs_pending < MAX_PENDING_REQUESTS )
		{
		DNS_Request* dns_req = nullptr;
		AsyncRequest* req = asyncs_queued.front();
		asyncs_queued.pop_front();

		++num_requests;
		req->time = util::current_time();

		if ( req->IsAddrReq() )
			dns_req = new DNS_Request(req->addr, true);
		else if ( req->is_txt )
			dns_req = new DNS_Request(req->host.c_str(), AF_UNSPEC, T_TXT, true);
		else
			// We pass T_A here, but because we're passing AF_UNSPEC MakeRequest() will
			// have c-ares attempt to lookup both ipv4 and ipv6 at the same time.
			dns_req = new DNS_Request(req->host.c_str(), AF_UNSPEC, T_A, true);

		dns_req->MakeRequest(channel);

		asyncs_timeouts.push(req);
		++asyncs_pending;
		}
	}

void DNS_Mgr::CheckAsyncHostRequest(const std::string& host, bool timeout)
	{
	// Note that this code is a mirror of that for CheckAsyncAddrRequest.

	AsyncRequestNameMap::iterator i = asyncs_names.find(host);

	if ( i != asyncs_names.end() )
		{
		if ( timeout )
			{
			++failed;
			i->second->Timeout();
			}
		else if ( auto addrs = LookupNameInCache(host, true, false) )
			{
			++successful;
			i->second->Resolved(addrs);
			}
		else
			return;

		delete i->second;
		asyncs_names.erase(i);
		--asyncs_pending;
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
		if ( timeout )
			{
			++failed;
			i->second->Timeout();
			}
		else if ( auto name = LookupAddrInCache(addr, true, false) )
			{
			++successful;
			i->second->Resolved(name->CheckString());
			}
		else
			return;

		delete i->second;
		asyncs_addrs.erase(i);
		--asyncs_pending;
		}
	}

void DNS_Mgr::CheckAsyncTextRequest(const std::string& host, bool timeout)
	{
	// Note that this code is a mirror of that for CheckAsyncAddrRequest.

	AsyncRequestTextMap::iterator i = asyncs_texts.find(host);
	if ( i != asyncs_texts.end() )
		{
		if ( timeout )
			{
			AsyncRequestTextMap::iterator it = asyncs_texts.begin();
			++failed;
			i->second->Timeout();
			}
		else if ( auto name = LookupTextInCache(host, true) )
			{
			++successful;
			i->second->Resolved(name->CheckString());
			}
		else
			return;

		delete i->second;
		asyncs_texts.erase(i);
		--asyncs_pending;
		}
	}

void DNS_Mgr::Flush()
	{
	Resolve();

	for ( HostMap::iterator it = host_mappings.begin(); it != host_mappings.end(); ++it )
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
	// If iosource_mgr says that we got a result on the socket fd, we don't have to ask c-ares
	// to retrieve it for us. We have the file descriptor already, just call ares_process_fd()
	// with it. Unfortunately, we may also have sockets close during this call, so we need to
	// to make a copy of the list first. Having a list change while looping over it can
	// cause segfaults.
	decltype(socket_fds) temp_fds{socket_fds};

	for ( int fd : temp_fds )
		{
		// double check this one wasn't removed already before trying to process it
		if ( socket_fds.count(fd) != 0 )
			ares_process_fd(channel, fd, ARES_SOCKET_BAD);
		}

	IssueAsyncRequests();
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

void DNS_Mgr::AsyncRequest::Resolved(const std::string& name)
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

void DNS_Mgr::AsyncRequest::Resolved(TableValPtr addrs)
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

static std::vector<IPAddr> get_result_addresses(TableValPtr addrs)
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
	void Resolved(const std::string& name) override
		{
		host_result = name;
		done = true;
		}
	void Resolved(TableValPtr addrs) override
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

/**
 * Derived testing version of DNS_Mgr so that the Process() method can be exposed
 * publically. If new unit tests are added, this class should be used over using
 * DNS_Mgr directly.
 */
class TestDNS_Mgr final : public DNS_Mgr
	{
public:
	explicit TestDNS_Mgr(DNS_MgrMode mode) : DNS_Mgr(mode) { }
	void Process();
	};

void TestDNS_Mgr::Process()
	{
	// Only allow usage of this method when running unit tests.
	assert(doctest::is_running_in_test);
	Resolve();
	IssueAsyncRequests();
	}

TEST_CASE("dns_mgr priming")
	{
	char prefix[] = "/tmp/zeek-unit-test-XXXXXX";
	auto tmpdir = mkdtemp(prefix);

	// Create a manager to prime the cache, make a few requests, and the save
	// the result. This tests that the priming code will create the requests but
	// wait for Resolve() to actually make the requests.
	TestDNS_Mgr mgr(DNS_PRIME);
	dns_mgr = &mgr;
	mgr.SetDir(tmpdir);
	mgr.InitPostScript();

	auto host_result = mgr.LookupHost("one.one.one.one");
	REQUIRE(host_result != nullptr);
	CHECK(host_result->EqualTo(TestDNS_Mgr::empty_addr_set()));

	IPAddr ones("1.1.1.1");
	auto addr_result = mgr.LookupAddr(ones);
	CHECK(strcmp(addr_result->CheckString(), "<none>") == 0);

	// This should wait until we have all of the results back from the above
	// requests.
	mgr.Resolve();

	// Save off the resulting values from Resolve() into a file on disk
	// in the tmpdir created by mkdtemp.
	REQUIRE(mgr.Save());

	// Make a second DNS manager and reload the cache that we just saved.
	TestDNS_Mgr mgr2(DNS_FORCE);
	dns_mgr = &mgr2;
	mgr2.SetDir(tmpdir);
	mgr2.InitPostScript();

	// Make the same two requests, but verify that we're correctly getting
	// data out of the cache.
	host_result = mgr2.LookupHost("one.one.one.one");
	REQUIRE(host_result != nullptr);
	CHECK_FALSE(host_result->EqualTo(TestDNS_Mgr::empty_addr_set()));

	addr_result = mgr2.LookupAddr(ones);
	REQUIRE(addr_result != nullptr);
	CHECK(strcmp(addr_result->CheckString(), "one.one.one.one") == 0);

	// Clean up cache file and the temp directory
	unlink(mgr2.CacheFile().c_str());
	rmdir(tmpdir);
	}

TEST_CASE("dns_mgr alternate server")
	{
	char* old_server = getenv("ZEEK_DNS_RESOLVER");

	setenv("ZEEK_DNS_RESOLVER", "1.1.1.1", 1);
	TestDNS_Mgr mgr(DNS_DEFAULT);
	dns_mgr = &mgr;

	mgr.InitPostScript();

	auto result = mgr.LookupAddr("1.1.1.1");
	REQUIRE(result != nullptr);
	CHECK(strcmp(result->CheckString(), "one.one.one.one") == 0);

	// FIXME: This won't run on systems without IPv6 connectivity.
	// setenv("ZEEK_DNS_RESOLVER", "2606:4700:4700::1111", 1);
	// TestDNS_Mgr mgr2(DNS_DEFAULT, true);
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
	TestDNS_Mgr mgr(DNS_DEFAULT);
	dns_mgr = &mgr;
	mgr.InitPostScript();

	IPAddr ones("1.1.1.1");
	auto host_result = mgr.LookupHost("one.one.one.one");
	REQUIRE(host_result != nullptr);
	CHECK_FALSE(host_result->EqualTo(TestDNS_Mgr::empty_addr_set()));

	auto addrs_from_request = get_result_addresses(host_result);
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
	TestDNS_Mgr mgr(DNS_DEFAULT);
	dns_mgr = &mgr;
	mgr.InitPostScript();

	TestCallback cb{};
	mgr.LookupHost("one.one.one.one", &cb);

	// This shouldn't take any longer than DNS_TIMEOUT+1 seconds, so bound it
	// just in case of some failure we're not aware of yet.
	int count = 0;
	while ( ! cb.done && (count < DNS_TIMEOUT + 1) )
		{
		mgr.Process();
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
	TestDNS_Mgr mgr(DNS_DEFAULT);
	dns_mgr = &mgr;
	mgr.InitPostScript();

	TestCallback cb{};
	mgr.LookupAddr(IPAddr{"1.1.1.1"}, &cb);

	// This shouldn't take any longer than DNS_TIMEOUT +1 seconds, so bound it
	// just in case of some failure we're not aware of yet.
	int count = 0;
	while ( ! cb.done && (count < DNS_TIMEOUT + 1) )
		{
		mgr.Process();
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
	TestDNS_Mgr mgr(DNS_DEFAULT);
	dns_mgr = &mgr;
	mgr.InitPostScript();

	TestCallback cb{};
	mgr.Lookup("unittest.zeek.org", T_TXT, &cb);

	// This shouldn't take any longer than DNS_TIMEOUT +1 seconds, so bound it
	// just in case of some failure we're not aware of yet.
	int count = 0;
	while ( ! cb.done && (count < DNS_TIMEOUT + 1) )
		{
		mgr.Process();
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
	TestDNS_Mgr mgr(DNS_DEFAULT);
	dns_mgr = &mgr;

	mgr.InitPostScript();
	auto addr_result = mgr.LookupAddr("1.1.1.1");
	REQUIRE(addr_result != nullptr);
	CHECK(strcmp(addr_result->CheckString(), "1.1.1.1") == 0);

	auto host_result = mgr.LookupHost("one.one.one.one");
	REQUIRE(host_result != nullptr);
	auto addresses = get_result_addresses(host_result);
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
	TestDNS_Mgr mgr(DNS_DEFAULT);
	dns_mgr = &mgr;
	mgr.InitPostScript();

	TestCallback cb{};
	mgr.Lookup("unittest.zeek.org", T_TXT, &cb);

	// This shouldn't take any longer than DNS_TIMEOUT +1 seconds, so bound it
	// just in case of some failure we're not aware of yet.
	int count = 0;
	while ( ! cb.done && (count < DNS_TIMEOUT + 1) )
		{
		mgr.Process();
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
