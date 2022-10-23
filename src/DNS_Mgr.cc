// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/DNS_Mgr.h"

#include "zeek/zeek-config.h"

#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <vector>

#ifdef TIME_WITH_SYS_TIME
#include <sys/time.h>
#include <ctime>
#elif defined(HAVE_SYS_TIME_H)
#include <sys/time.h>
#else
#include <ctime>
#endif

#include <ztd/out_ptr.hpp>
using ztd::out_ptr::out_ptr;

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

// The maximum number of bytes requested via UDP. TCP fallback won't happen on
// requests until a response is larger than this.
constexpr int MAX_UDP_BUFFER_SIZE = 4096;

// This unfortunately doesn't exist in c-ares, even though it seems rather useful.
static const char* request_type_string(int request_type)
	{
	switch ( request_type )
		{
		case T_A:
			return "T_A";
		case T_NS:
			return "T_NS";
		case T_MD:
			return "T_MD";
		case T_MF:
			return "T_MF";
		case T_CNAME:
			return "T_CNAME";
		case T_SOA:
			return "T_SOA";
		case T_MB:
			return "T_MB";
		case T_MG:
			return "T_MG";
		case T_MR:
			return "T_MR";
		case T_NULL:
			return "T_NULL";
		case T_WKS:
			return "T_WKS";
		case T_PTR:
			return "T_PTR";
		case T_HINFO:
			return "T_HINFO";
		case T_MINFO:
			return "T_MINFO";
		case T_MX:
			return "T_MX";
		case T_TXT:
			return "T_TXT";
		case T_RP:
			return "T_RP";
		case T_AFSDB:
			return "T_AFSDB";
		case T_X25:
			return "T_X25";
		case T_ISDN:
			return "T_ISDN";
		case T_RT:
			return "T_RT";
		case T_NSAP:
			return "T_NSAP";
		case T_NSAP_PTR:
			return "T_NSAP_PTR";
		case T_SIG:
			return "T_SIG";
		case T_KEY:
			return "T_KEY";
		case T_PX:
			return "T_PX";
		case T_GPOS:
			return "T_GPOS";
		case T_AAAA:
			return "T_AAAA";
		case T_LOC:
			return "T_LOC";
		case T_NXT:
			return "T_NXT";
		case T_EID:
			return "T_EID";
		case T_NIMLOC:
			return "T_NIMLOC";
		case T_SRV:
			return "T_SRV";
		case T_ATMA:
			return "T_ATMA";
		case T_NAPTR:
			return "T_NAPTR";
		case T_KX:
			return "T_KX";
		case T_CERT:
			return "T_CERT";
		case T_A6:
			return "T_A6";
		case T_DNAME:
			return "T_DNAME";
		case T_SINK:
			return "T_SINK";
		case T_OPT:
			return "T_OPT";
		case T_APL:
			return "T_APL";
		case T_DS:
			return "T_DS";
		case T_SSHFP:
			return "T_SSHFP";
		case T_RRSIG:
			return "T_RRSIG";
		case T_NSEC:
			return "T_NSEC";
		case T_DNSKEY:
			return "T_DNSKEY";
		case T_TKEY:
			return "T_TKEY";
		case T_TSIG:
			return "T_TSIG";
		case T_IXFR:
			return "T_IXFR";
		case T_AXFR:
			return "T_AXFR";
		case T_MAILB:
			return "T_MAILB";
		case T_MAILA:
			return "T_MAILA";
		case T_ANY:
			return "T_ANY";
		case T_URI:
			return "T_URI";
		case T_CAA:
			return "T_CAA";
		case T_MAX:
			return "T_MAX";
		default:
			return "";
		}
	}

struct ares_deleter
	{
	void operator()(char* s) const { ares_free_string(s); }
	void operator()(unsigned char* s) const { ares_free_string(s); }
	void operator()(ares_addrinfo* s) const { ares_freeaddrinfo(s); }
	void operator()(struct hostent* h) const { ares_free_hostent(h); }
	void operator()(struct ares_txt_reply* h) const { ares_free_data(h); }
	};

namespace zeek::detail
	{
static void addrinfo_cb(void* arg, int status, int timeouts, struct ares_addrinfo* result);
static void query_cb(void* arg, int status, int timeouts, unsigned char* buf, int len);
static void sock_cb(void* data, int s, int read, int write);

struct CallbackArgs
	{
	DNS_Request* req;
	DNS_Mgr* mgr;
	};

class DNS_Request
	{
public:
	DNS_Request(std::string host, int request_type, bool async = false);
	DNS_Request(const IPAddr& addr, bool async = false);
	~DNS_Request();

	std::string Host() const { return host; }
	const IPAddr& Addr() const { return addr; }
	int RequestType() const { return request_type; }
	bool IsTxt() const { return request_type == 16; }

	void MakeRequest(ares_channel channel, DNS_Mgr* mgr);
	void ProcessAsyncResult(bool timed_out, DNS_Mgr* mgr);

private:
	std::string host;
	IPAddr addr;
	int request_type = 0; // Query type
	bool async = false;
	std::unique_ptr<unsigned char, ares_deleter> query;
	static uint16_t request_id;
	};

uint16_t DNS_Request::request_id = 0;

DNS_Request::DNS_Request(std::string host, int request_type, bool async)
	: host(std::move(host)), request_type(request_type), async(async)
	{
	// We combine the T_A and T_AAAA requests together in one request, so set the type
	// to T_A to make things easier in other parts of the code (mostly around lookups).
	if ( request_type == T_AAAA )
		request_type = T_A;
	}

DNS_Request::DNS_Request(const IPAddr& addr, bool async) : addr(addr), async(async)
	{
	request_type = T_PTR;
	}

DNS_Request::~DNS_Request() { }

void DNS_Request::MakeRequest(ares_channel channel, DNS_Mgr* mgr)
	{
	// This needs to get deleted at the end of the callback method.
	auto req_data = std::make_unique<CallbackArgs>();
	req_data->req = this;
	req_data->mgr = mgr;

	// It's completely fine if this rolls over. It's just to keep the query ID different
	// from one query to the next, and it's unlikely we'd do 2^16 queries so fast that
	// all of them would be in flight at the same time.
	DNS_Request::request_id++;

	if ( request_type == T_A )
		{
		// For A/AAAA requests, we use a different method than the other requests. Since
		// we're using the AF_UNSPEC family, we get both the ipv4 and ipv6 responses
		// back in the same request if use ares_getaddrinfo() so we can store them both
		// in the same mapping.
		ares_addrinfo_hints hints = {ARES_AI_CANONNAME, AF_UNSPEC, 0, 0};
		ares_getaddrinfo(channel, host.c_str(), NULL, &hints, addrinfo_cb, req_data.release());
		}
	else
		{
		std::string query_host;
		if ( request_type == T_PTR )
			query_host = addr.PtrName();
		else
			query_host = host;

		std::unique_ptr<unsigned char, ares_deleter> query_str;
		int len = 0;
		int status = ares_create_query(
			query_host.c_str(), C_IN, request_type, DNS_Request::request_id, 1,
			out_ptr<unsigned char*>(query_str), &len, MAX_UDP_BUFFER_SIZE);

		if ( status != ARES_SUCCESS || query_str == nullptr )
			return;

		// Store this so it can be destroyed when the request is destroyed.
		this->query = std::move(query_str);
		ares_send(channel, this->query.get(), len, query_cb, req_data.release());
		}
	}

void DNS_Request::ProcessAsyncResult(bool timed_out, DNS_Mgr* mgr)
	{
	if ( ! async )
		return;

	if ( request_type == T_A )
		mgr->CheckAsyncHostRequest(host, timed_out);
	else if ( request_type == T_PTR )
		mgr->CheckAsyncAddrRequest(addr, timed_out);
	else
		mgr->CheckAsyncOtherRequest(host, timed_out, request_type);
	}

/**
 * Retrieves the TTL value from the first RR in the response.
 *
 * This code is adapted from an internal c-ares method called * ares__parse_into_addrinfo,
 * which is used for ares_getaddrinfo callbacks. It's also the only method that properly
 * parses out TTL data currently. This skips over the question and the first bit of the
 * response to get to the first RR, and then returns the TTL from that RR. We only use the
 * first RR because it's a good approximation for now, at least until the work in c-ares
 * lands to add TTL support to the other RR-parsing methods.
 *
 * @param abuf The buffer containing the entire response from the server.
 * @param alen The length of the buffer
 * @param ttl An out param for returning the TTL value.
 * @return A status code from c-ares. This will be ARES_SUCCESS on success, or some other
 * code on failure.
 */
static int get_ttl(unsigned char* abuf, int alen, int* ttl)
	{
	int status;
	long len;
	std::unique_ptr<char, ares_deleter> hostname;

	*ttl = DNS_TIMEOUT;

	unsigned char* aptr = abuf + HFIXEDSZ;
	status = ares_expand_name(aptr, abuf, alen, out_ptr<char*>(hostname), &len);
	if ( status != ARES_SUCCESS )
		return status;

	if ( aptr + len + QFIXEDSZ > abuf + alen )
		return ARES_EBADRESP;

	aptr += len + QFIXEDSZ;
	hostname.reset();

	status = ares_expand_name(aptr, abuf, alen, out_ptr<char*>(hostname), &len);
	if ( status != ARES_SUCCESS )
		return status;

	if ( aptr + RRFIXEDSZ > abuf + alen )
		return ARES_EBADRESP;

	aptr += len;
	*ttl = DNS_RR_TTL(aptr);

	return status;
	}

/**
 * Called in response to ares_getaddrinfo requests. Builds a hostent structure from
 * the result data and sends it to the DNS manager via AddResult().
 */
static void addrinfo_cb(void* arg, int status, int timeouts, struct ares_addrinfo* result)
	{
	auto arg_data = reinterpret_cast<CallbackArgs*>(arg);
	const auto [req, mgr] = *arg_data;
	std::unique_ptr<ares_addrinfo, ares_deleter> res_ptr(result);

	if ( status != ARES_SUCCESS )
		{
		// These two statuses should only ever be sent if we're shutting down everything
		// and all of the existing queries are being cancelled. There's no reason to
		// store a status that's just going to get deleted, nor is there a reason to log
		// anything.
		if ( status != ARES_ECANCELLED && status != ARES_EDESTRUCTION )
			{
			// Insert something into the cache so that the request loop will end correctly.
			// We use the DNS_TIMEOUT value as the TTL here since it's small enough that the
			// failed response will expire soon, and because we don't have the TTL from the
			// response data.
			mgr->AddResult(req, nullptr, DNS_TIMEOUT);
			}
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

			struct hostent he
				{
				};
			he.h_name = util::copy_string(result->name);
			he.h_addrtype = AF_INET;
			he.h_length = sizeof(in_addr);
			he.h_addr_list = reinterpret_cast<char**>(addrs.data());

			mgr->AddResult(req, &he, result->nodes[0].ai_ttl);

			delete[] he.h_name;
			}

		if ( ! addrs6.empty() )
			{
			// Push a null on the end so the addr list has a final point during later parsing.
			addrs6.push_back(NULL);

			struct hostent he
				{
				};
			he.h_name = util::copy_string(result->name);
			he.h_addrtype = AF_INET6;
			he.h_length = sizeof(in6_addr);
			he.h_addr_list = reinterpret_cast<char**>(addrs6.data());

			mgr->AddResult(req, &he, result->nodes[0].ai_ttl, true);

			delete[] he.h_name;
			}
		}

	req->ProcessAsyncResult(timeouts > 0, mgr);

	// TODO: might need to turn these into unique_ptr as well?
	delete req;
	delete arg_data;
	}

static void query_cb(void* arg, int status, int timeouts, unsigned char* buf, int len)
	{
	auto arg_data = reinterpret_cast<CallbackArgs*>(arg);
	const auto [req, mgr] = *arg_data;

	if ( status != ARES_SUCCESS )
		{
		// These two statuses should only ever be sent if we're shutting down everything
		// and all of the existing queries are being cancelled. There's no reason to
		// store a status that's just going to get deleted, nor is there a reason to log
		// anything.
		if ( status != ARES_ECANCELLED && status != ARES_EDESTRUCTION )
			{
			// Insert something into the cache so that the request loop will end correctly.
			// We use the DNS_TIMEOUT value as the TTL here since it's small enough that the
			// failed response will expire soon, and because we don't have the TTL from the
			// response data.
			mgr->AddResult(req, nullptr, DNS_TIMEOUT);
			}
		}
	else
		{
		// We don't really care that we couldn't properly parse the TTL here, since the
		// later parsing will fail with better error messages. In that case, it's ok
		// that we throw away the status value.
		int ttl;
		get_ttl(buf, len, &ttl);

		switch ( req->RequestType() )
			{
			case T_PTR:
				{
				std::unique_ptr<struct hostent, ares_deleter> he;
				if ( req->Addr().GetFamily() == IPv4 )
					{
					struct in_addr addr;
					req->Addr().CopyIPv4(&addr);
					status = ares_parse_ptr_reply(buf, len, &addr, sizeof(addr), AF_INET,
					                              out_ptr<struct hostent*>(he));
					}
				else
					{
					struct in6_addr addr;
					req->Addr().CopyIPv6(&addr);
					status = ares_parse_ptr_reply(buf, len, &addr, sizeof(addr), AF_INET6,
					                              out_ptr<struct hostent*>(he));
					}

				if ( status == ARES_SUCCESS )
					mgr->AddResult(req, he.get(), ttl);
				else
					{
					// See above for why DNS_TIMEOUT here.
					mgr->AddResult(req, nullptr, DNS_TIMEOUT);
					}
				break;
				}
			case T_TXT:
				{
				std::unique_ptr<struct ares_txt_reply, ares_deleter> reply;
				int r = ares_parse_txt_reply(buf, len, out_ptr<struct ares_txt_reply*>(reply));
				if ( r == ARES_SUCCESS )
					{
					// Use a hostent to send the data into AddResult(). We only care about
					// setting the host field, but everything else should be zero just for
					// safety.

					// We don't currently handle more than the first response, and throw the
					// rest away. There really isn't a good reason for this, we just haven't
					// ever done so. It would likely require some changes to the output from
					// Lookup(), since right now it only returns one value.
					struct hostent he
						{
						};
					he.h_name = util::copy_string(reinterpret_cast<const char*>(reply->txt));
					mgr->AddResult(req, &he, ttl);

					delete[] he.h_name;
					}
				else
					{
					// See above for why DNS_TIMEOUT here.
					mgr->AddResult(req, nullptr, DNS_TIMEOUT);
					}

				break;
				}

			default:
				reporter->Error("Requests of type %d (%s) are unsupported", req->RequestType(),
				                request_type_string(req->RequestType()));
				break;
			}
		}

	req->ProcessAsyncResult(timeouts > 0, mgr);
	delete arg_data;
	delete req;
	}

/**
 * Called when the c-ares socket changes state, which indicates that it's connected to
 * some source of data (either a host file or a DNS server). This indicates that we're
 * able to do lookups against c-ares now and should activate the IOSource.
 */
static void sock_cb(void* data, int s, int read, int write)
	{
	auto mgr = reinterpret_cast<DNS_Mgr*>(data);
	mgr->RegisterSocket(s, read == 1, write == 1);
	}

DNS_Mgr::DNS_Mgr(DNS_MgrMode arg_mode) : IOSource(true), mode(arg_mode)
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

void DNS_Mgr::Done()
	{
	shutting_down = true;
	Flush();
	}

void DNS_Mgr::RegisterSocket(int fd, bool read, bool write)
	{
	if ( read && socket_fds.count(fd) == 0 )
		{
		socket_fds.insert(fd);
		iosource_mgr->RegisterFd(fd, this, IOSource::READ);
		}
	else if ( ! read && socket_fds.count(fd) != 0 )
		{
		socket_fds.erase(fd);
		iosource_mgr->UnregisterFd(fd, this, IOSource::READ);
		}

	if ( write && write_socket_fds.count(fd) == 0 )
		{
		write_socket_fds.insert(fd);
		iosource_mgr->RegisterFd(fd, this, IOSource::WRITE);
		}
	else if ( ! write && write_socket_fds.count(fd) != 0 )
		{
		write_socket_fds.erase(fd);
		iosource_mgr->UnregisterFd(fd, this, IOSource::WRITE);
		}
	}

void DNS_Mgr::InitSource()
	{
	if ( did_init )
		return;

	ares_options options;
	int optmask = 0;

	// Enable an EDNS option to be sent with the requests. This allows us to set
	// a bigger UDP buffer size in the request, which prevents fallback to TCP
	// at least up to that size.
	options.flags = ARES_FLAG_EDNS;
	optmask |= ARES_OPT_FLAGS;

	options.ednspsz = MAX_UDP_BUFFER_SIZE;
	optmask |= ARES_OPT_EDNSPSZ;

	options.socket_receive_buffer_size = MAX_UDP_BUFFER_SIZE;
	optmask |= ARES_OPT_SOCK_RCVBUF;

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

static std::string fake_lookup_result(const std::string& name, int request_type)
	{
	return util::fmt("fake_lookup_result_%s_%s", request_type_string(request_type), name.c_str());
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
	if ( shutting_down )
		return nullptr;

	if ( request_type == T_A || request_type == T_AAAA )
		return LookupHost(name);

	if ( mode == DNS_FAKE )
		return make_intrusive<StringVal>(fake_lookup_result(name, request_type));

	InitSource();

	if ( mode != DNS_PRIME )
		{
		if ( auto val = LookupOtherInCache(name, request_type, false) )
			return val;
		}

	switch ( mode )
		{
		case DNS_PRIME:
			{
			auto req = new DNS_Request(name, request_type);
			req->MakeRequest(channel, this);
			return empty_addr_set();
			}

		case DNS_FORCE:
			reporter->FatalError("can't find DNS entry for %s (req type %d / %s) in cache",
			                     name.c_str(), request_type, request_type_string(request_type));
			return nullptr;

		case DNS_DEFAULT:
			{
			auto req = new DNS_Request(name, request_type);
			req->MakeRequest(channel, this);
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
	if ( shutting_down )
		return nullptr;

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
			// We pass T_A here, but DNSRequest::MakeRequest() will special-case that in
			// a request that gets both T_A and T_AAAA results at one time.
			auto req = new DNS_Request(name, T_A);
			req->MakeRequest(channel, this);
			return empty_addr_set();
			}

		case DNS_FORCE:
			reporter->FatalError("can't find DNS entry for %s in cache", name.c_str());
			return nullptr;

		case DNS_DEFAULT:
			{
			// We pass T_A here, but DNSRequest::MakeRequest() will special-case that in
			// a request that gets both T_A and T_AAAA results at one time.
			auto req = new DNS_Request(name, T_A);
			req->MakeRequest(channel, this);
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
	if ( shutting_down )
		return nullptr;

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
			req->MakeRequest(channel, this);
			return make_intrusive<StringVal>("<none>");
			}

		case DNS_FORCE:
			reporter->FatalError("can't find DNS entry for %s in cache", addr.AsString().c_str());
			return nullptr;

		case DNS_DEFAULT:
			{
			auto req = new DNS_Request(addr);
			req->MakeRequest(channel, this);
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
	if ( shutting_down )
		return;

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
	auto key = std::make_pair(T_A, name);
	auto i = asyncs.find(key);
	if ( i != asyncs.end() )
		req = i->second;
	else
		{
		// A new one.
		req = new AsyncRequest{name, T_A};
		asyncs_queued.push_back(req);
		asyncs.emplace_hint(i, std::move(key), req);
		}

	req->callbacks.push_back(callback);

	// There may be requests in the queue that haven't been processed yet
	// so go ahead and reissue them, even if this method didn't change
	// anything.
	IssueAsyncRequests();
	}

void DNS_Mgr::LookupAddr(const IPAddr& addr, LookupCallback* callback)
	{
	if ( shutting_down )
		return;

	if ( mode == DNS_FAKE )
		{
		resolve_lookup_cb(callback, fake_addr_lookup_result(addr));
		return;
		}

	// Do we already know the answer?
	if ( auto name = LookupAddrInCache(addr, true, false) )
		{
		resolve_lookup_cb(callback, name->CheckString());
		return;
		}

	AsyncRequest* req = nullptr;

	// If we already have a request waiting for this host, we don't need to make
	// another one. We can just add the callback to it and it'll get handled
	// when the first request comes back.
	auto i = asyncs.find(addr);
	if ( i != asyncs.end() )
		req = i->second;
	else
		{
		// A new one.
		req = new AsyncRequest{addr};
		asyncs_queued.push_back(req);
		asyncs.emplace_hint(i, addr, req);
		}

	req->callbacks.push_back(callback);

	// There may be requests in the queue that haven't been processed yet
	// so go ahead and reissue them, even if this method didn't change
	// anything.
	IssueAsyncRequests();
	}

void DNS_Mgr::Lookup(const std::string& name, int request_type, LookupCallback* callback)
	{
	if ( shutting_down )
		return;

	if ( mode == DNS_FAKE )
		{
		resolve_lookup_cb(callback, fake_lookup_result(name, request_type));
		return;
		}

	// Do we already know the answer?
	if ( auto txt = LookupOtherInCache(name, request_type, true) )
		{
		resolve_lookup_cb(callback, txt->CheckString());
		return;
		}

	AsyncRequest* req = nullptr;

	// If we already have a request waiting for this host, we don't need to make
	// another one. We can just add the callback to it and it'll get handled
	// when the first request comes back.
	auto key = std::make_pair(request_type, name);
	auto i = asyncs.find(key);
	if ( i != asyncs.end() )
		req = i->second;
	else
		{
		// A new one.
		req = new AsyncRequest{name, request_type};
		asyncs_queued.push_back(req);
		asyncs.emplace_hint(i, std::move(key), req);
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
		int res = select(nfds, &read_fds, &write_fds, NULL, tvp);
		if ( res >= 0 )
			ares_process(channel, &read_fds, &write_fds);
		}
	}

void DNS_Mgr::Event(EventHandlerPtr e, const DNS_MappingPtr& dm)
	{
	if ( e )
		event_mgr.Enqueue(e, BuildMappingVal(dm));
	}

void DNS_Mgr::Event(EventHandlerPtr e, const DNS_MappingPtr& dm, ListValPtr l1, ListValPtr l2)
	{
	if ( e )
		event_mgr.Enqueue(e, BuildMappingVal(dm), l1->ToSetVal(), l2->ToSetVal());
	}

void DNS_Mgr::Event(EventHandlerPtr e, const DNS_MappingPtr& old_dm, DNS_MappingPtr new_dm)
	{
	if ( e )
		event_mgr.Enqueue(e, BuildMappingVal(old_dm), BuildMappingVal(new_dm));
	}

ValPtr DNS_Mgr::BuildMappingVal(const DNS_MappingPtr& dm)
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

void DNS_Mgr::AddResult(DNS_Request* dr, struct hostent* h, uint32_t ttl, bool merge)
	{
	// TODO: the existing code doesn't handle hostname aliases at all. Should we?

	DNS_MappingPtr new_mapping = nullptr;
	DNS_MappingPtr prev_mapping = nullptr;
	bool keep_prev = true;

	MappingMap::iterator it;
	if ( dr->RequestType() == T_PTR )
		{
		new_mapping = std::make_shared<DNS_Mapping>(dr->Addr(), h, ttl);
		it = all_mappings.find(dr->Addr());
		if ( it == all_mappings.end() )
			{
			auto result = all_mappings.emplace(dr->Addr(), new_mapping);
			it = result.first;
			}
		else
			prev_mapping = it->second;
		}
	else
		{
		new_mapping = std::make_shared<DNS_Mapping>(dr->Host(), h, ttl, dr->RequestType());
		auto key = std::make_pair(dr->RequestType(), dr->Host());

		it = all_mappings.find(key);
		if ( it == all_mappings.end() )
			{
			auto result = all_mappings.emplace(std::move(key), new_mapping);
			it = result.first;
			}
		else
			prev_mapping = it->second;
		}

	if ( prev_mapping && prev_mapping->Valid() )
		{
		if ( new_mapping->Valid() )
			{
			if ( merge )
				new_mapping->Merge(prev_mapping);

			it->second = new_mapping;
			keep_prev = false;
			}
		}
	else
		{
		it->second = new_mapping;
		keep_prev = false;
		}

	if ( prev_mapping && ! dr->IsTxt() )
		CompareMappings(prev_mapping, new_mapping);

	if ( keep_prev )
		new_mapping.reset();
	else
		prev_mapping.reset();
	}

void DNS_Mgr::CompareMappings(const DNS_MappingPtr& prev_mapping, const DNS_MappingPtr& new_mapping)
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

	auto prev_delta = AddrListDelta(prev_a, new_a);
	auto new_delta = AddrListDelta(new_a, prev_a);

	if ( prev_delta->Length() > 0 || new_delta->Length() > 0 )
		Event(dns_mapping_altered, new_mapping, std::move(prev_delta), std::move(new_delta));
	}

ListValPtr DNS_Mgr::AddrListDelta(ListValPtr al1, ListValPtr al2)
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

	if ( ! DNS_Mapping::ValidateCacheVersion(f) )
		{
		fclose(f);
		return;
		}

	// Loop until we find a mapping that doesn't initialize correctly.
	auto m = std::make_shared<DNS_Mapping>(f);
	for ( ; ! m->NoMapping() && ! m->InitFailed(); m = std::make_shared<DNS_Mapping>(f) )
		{
		if ( m->ReqHost() )
			all_mappings.insert_or_assign(std::make_pair(m->ReqType(), m->ReqHost()), m);
		else
			all_mappings.insert_or_assign(m->ReqAddr(), m);
		}

	if ( ! m->NoMapping() )
		reporter->FatalError("DNS cache corrupted");

	fclose(f);
	}

bool DNS_Mgr::Save()
	{
	if ( cache_name.empty() )
		return false;

	FILE* f = fopen(cache_name.c_str(), "w");

	if ( ! f )
		return false;

	DNS_Mapping::InitializeCache(f);
	Save(f, all_mappings);

	fclose(f);

	return true;
	}

void DNS_Mgr::Save(FILE* f, const MappingMap& m)
	{
	for ( const auto& [key, mapping] : m )
		{
		if ( mapping )
			mapping->Save(f);
		}
	}

TableValPtr DNS_Mgr::LookupNameInCache(const std::string& name, bool cleanup_expired,
                                       bool check_failed)
	{
	auto it = all_mappings.find(std::make_pair(T_A, name));
	if ( it == all_mappings.end() )
		return nullptr;

	auto d = it->second;

	if ( ! d || d->names.empty() )
		return nullptr;

	if ( cleanup_expired && (d && d->Expired()) )
		{
		all_mappings.erase(it);
		return nullptr;
		}

	if ( check_failed && (d && d->Failed()) )
		{
		reporter->Warning("Can't resolve host: %s", name.c_str());
		return empty_addr_set();
		}

	return d->AddrsSet();
	}

StringValPtr DNS_Mgr::LookupAddrInCache(const IPAddr& addr, bool cleanup_expired, bool check_failed)
	{
	auto it = all_mappings.find(addr);
	if ( it == all_mappings.end() )
		return nullptr;

	auto d = it->second;

	if ( cleanup_expired && d->Expired() )
		{
		all_mappings.erase(it);
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

StringValPtr DNS_Mgr::LookupOtherInCache(const std::string& name, int request_type,
                                         bool cleanup_expired)
	{
	auto it = all_mappings.find(std::make_pair(request_type, name));
	if ( it == all_mappings.end() )
		return nullptr;

	auto d = it->second;

	if ( cleanup_expired && d->Expired() )
		{
		all_mappings.erase(it);
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

		if ( req->type == T_PTR )
			dns_req = new DNS_Request(req->addr, true);
		else if ( req->type == T_A || req->type == T_AAAA )
			// We pass T_A here, but DNSRequest::MakeRequest() will special-case that in
			// a request that gets both T_A and T_AAAA results at one time.
			dns_req = new DNS_Request(req->host.c_str(), T_A, true);
		else
			dns_req = new DNS_Request(req->host.c_str(), req->type, true);

		dns_req->MakeRequest(channel, this);

		++asyncs_pending;
		}
	}

void DNS_Mgr::CheckAsyncHostRequest(const std::string& host, bool timeout)
	{
	// Note that this code is a mirror of that for CheckAsyncAddrRequest.
	auto i = asyncs.find(std::make_pair(T_A, host));

	if ( i != asyncs.end() )
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
		asyncs.erase(i);
		--asyncs_pending;
		}
	}

void DNS_Mgr::CheckAsyncAddrRequest(const IPAddr& addr, bool timeout)
	{
	// Note that this code is a mirror of that for CheckAsyncHostRequest.

	// In the following, if it's not in the respective map anymore, we've
	// already finished it earlier and don't have anything to do.
	auto i = asyncs.find(addr);

	if ( i != asyncs.end() )
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
		asyncs.erase(i);
		--asyncs_pending;
		}
	}

void DNS_Mgr::CheckAsyncOtherRequest(const std::string& host, bool timeout, int request_type)
	{
	// Note that this code is a mirror of that for CheckAsyncAddrRequest.

	auto i = asyncs.find(std::make_pair(request_type, host));
	if ( i != asyncs.end() )
		{
		if ( timeout )
			{
			++failed;
			i->second->Timeout();
			}
		else if ( auto name = LookupOtherInCache(host, request_type, true) )
			{
			++successful;
			i->second->Resolved(name->CheckString());
			}
		else
			return;

		delete i->second;
		asyncs.erase(i);
		--asyncs_pending;
		}
	}

void DNS_Mgr::Flush()
	{
	Resolve();
	all_mappings.clear();
	}

double DNS_Mgr::GetNextTimeout()
	{
	if ( asyncs_pending == 0 )
		return -1;

	fd_set read_fds, write_fds;

	FD_ZERO(&read_fds);
	FD_ZERO(&write_fds);
	int nfds = ares_fds(channel, &read_fds, &write_fds);
	if ( nfds == 0 )
		return -1;

	struct timeval tv;
	tv.tv_sec = DNS_TIMEOUT;
	tv.tv_usec = 0;

	struct timeval* tvp = ares_timeout(channel, &tv, &tv);

	return run_state::network_time + static_cast<double>(tvp->tv_sec) +
	       (static_cast<double>(tvp->tv_usec) / 1e6);
	}

void DNS_Mgr::ProcessFd(int fd, int flags)
	{
	if ( socket_fds.count(fd) != 0 )
		{
		int read_fd = (flags & IOSource::ProcessFlags::READ) != 0 ? fd : ARES_SOCKET_BAD;
		int write_fd = (flags & IOSource::ProcessFlags::WRITE) != 0 ? fd : ARES_SOCKET_BAD;
		ares_process_fd(channel, read_fd, write_fd);
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

	stats->cached_hosts = 0;
	stats->cached_addresses = 0;
	stats->cached_texts = 0;

	for ( const auto& [key, mapping] : all_mappings )
		{
		if ( mapping->ReqType() == T_PTR )
			stats->cached_addresses++;
		else if ( mapping->ReqType() == T_A )
			stats->cached_hosts++;
		else
			stats->cached_texts++;
		}
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

// Unit testing coverage for the DNS_Mgr code, including making actual DNS requests to
// test responses and timeouts. Note that all of these tests are marked with the skip
// decorator, since they take some time to run and this slows down local developement. To
// run them manually, pass the --no-skip flag when running tests. These tests are
// run automatically as part of CI builds.

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

TEST_CASE("dns_mgr priming" * doctest::skip(true))
	{
	char prefix[] = "/tmp/zeek-unit-test-XXXXXX";
	auto tmpdir = mkdtemp(prefix);

	// Create a manager to prime the cache, make a few requests, and the save
	// the result. This tests that the priming code will create the requests but
	// wait for Resolve() to actually make the requests.
	TestDNS_Mgr mgr(DNS_PRIME);
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

TEST_CASE("dns_mgr alternate server" * doctest::skip(true))
	{
	char* old_server = getenv("ZEEK_DNS_RESOLVER");

	setenv("ZEEK_DNS_RESOLVER", "1.1.1.1", 1);
	TestDNS_Mgr mgr(DNS_DEFAULT);

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

TEST_CASE("dns_mgr default mode" * doctest::skip(true))
	{
	TestDNS_Mgr mgr(DNS_DEFAULT);
	mgr.InitPostScript();

	IPAddr ones4("1.1.1.1");
	IPAddr ones6("2606:4700:4700::1111");

	auto host_result = mgr.LookupHost("one.one.one.one");
	REQUIRE(host_result != nullptr);
	CHECK_FALSE(host_result->EqualTo(TestDNS_Mgr::empty_addr_set()));

	auto addrs_from_request = get_result_addresses(host_result);
	auto it = std::find(addrs_from_request.begin(), addrs_from_request.end(), ones4);
	CHECK(it != addrs_from_request.end());
	it = std::find(addrs_from_request.begin(), addrs_from_request.end(), ones6);
	CHECK(it != addrs_from_request.end());

	auto addr_result = mgr.LookupAddr(ones4);
	REQUIRE(addr_result != nullptr);
	CHECK(strcmp(addr_result->CheckString(), "one.one.one.one") == 0);

	addr_result = mgr.LookupAddr(ones6);
	REQUIRE(addr_result != nullptr);
	CHECK(strcmp(addr_result->CheckString(), "one.one.one.one") == 0);

	IPAddr bad("240.0.0.0");
	addr_result = mgr.LookupAddr(bad);
	REQUIRE(addr_result != nullptr);
	CHECK(strcmp(addr_result->CheckString(), "240.0.0.0") == 0);
	}

TEST_CASE("dns_mgr async host" * doctest::skip(true))
	{
	TestDNS_Mgr mgr(DNS_DEFAULT);
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

TEST_CASE("dns_mgr async addr" * doctest::skip(true))
	{
	TestDNS_Mgr mgr(DNS_DEFAULT);
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

TEST_CASE("dns_mgr async text" * doctest::skip(true))
	{
	TestDNS_Mgr mgr(DNS_DEFAULT);
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

TEST_CASE("dns_mgr timeouts" * doctest::skip(true))
	{
	char* old_server = getenv("ZEEK_DNS_RESOLVER");

	// This is the address for blackhole.webpagetest.org, which provides a DNS
	// server that lets you connect but never returns any responses, always
	// resulting in a timeout.
	setenv("ZEEK_DNS_RESOLVER", "3.219.212.117", 1);
	TestDNS_Mgr mgr(DNS_DEFAULT);

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

TEST_CASE("dns_mgr async timeouts" * doctest::skip(true))
	{
	char* old_server = getenv("ZEEK_DNS_RESOLVER");

	// This is the address for blackhole.webpagetest.org, which provides a DNS
	// server that lets you connect but never returns any responses, always
	// resulting in a timeout.
	setenv("ZEEK_DNS_RESOLVER", "3.219.212.117", 1);
	TestDNS_Mgr mgr(DNS_DEFAULT);
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
