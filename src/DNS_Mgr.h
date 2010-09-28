// $Id: DNS_Mgr.h 6915 2009-09-22 05:04:17Z vern $
//
// See the file "COPYING" in the main distribution directory for copyright.

#ifndef dnsmgr_h
#define dnsmgr_h

#include <list>
#include <map>
#include <queue>

#include "util.h"
#include "BroList.h"
#include "Dict.h"
#include "EventHandler.h"
#include "IOSource.h"

class Val;
class ListVal;
class TableVal;
class Func;
class EventHandler;
class RecordType;
class DNS_Mgr_Request;

struct nb_dns_info;
struct nb_dns_result;

declare(PDict,ListVal);

class DNS_Mapping;
declare(PDict,DNS_Mapping);

enum DNS_MgrMode {
	DNS_PRIME,	// used to prime the cache
	DNS_FORCE,	// internal error if cache miss
	DNS_DEFAULT,	// lookup names as they're requested
	DNS_FAKE,	// don't look up names, just return dummy results
};

// Number of seconds we'll wait for a reply.
#define DNS_TIMEOUT 5

// ### For now, we don't support IPv6 lookups.  When we do, this
// should become addr_type.
typedef uint32 dns_mgr_addr_type;

class DNS_Mgr : public IOSource {
public:
	DNS_Mgr(DNS_MgrMode mode);
	virtual ~DNS_Mgr();

	bool Init();

	// Looks up the address or addresses of the given host, and returns
	// a set of addr.
	TableVal* LookupHost(const char* host);

	Val* LookupAddr(uint32 addr);

	// Define the directory where to store the data.
	void SetDir(const char* arg_dir)	{ dir = copy_string(arg_dir); }

	void Verify();
	void Resolve();
	int Save();

	const char* LookupAddrInCache(dns_mgr_addr_type addr);
	TableVal* LookupNameInCache(string name);

	// Support for async lookups.
	class LookupCallback {
	public:
		LookupCallback()	{ }
		virtual ~LookupCallback()	{ }

		virtual void Resolved(const char* name)	{ };
		virtual void Resolved(TableVal* addrs)	{ };
		virtual void Timeout() = 0;
	};

#ifdef HAVE_NB_DNS
	void AsyncLookupAddr(dns_mgr_addr_type host, LookupCallback* callback);
	void AsyncLookupName(string name, LookupCallback* callback);
#endif

protected:
	friend class LookupCallback;
	friend class DNS_Mgr_Request;

	void Event(EventHandlerPtr e, DNS_Mapping* dm,
			ListVal* l1 = 0, ListVal* l2 = 0);
	void Event(EventHandlerPtr e, DNS_Mapping* old_dm, DNS_Mapping* new_dm);

	Val* BuildMappingVal(DNS_Mapping* dm);

	void AddResult(DNS_Mgr_Request* dr, struct nb_dns_result* r);
	void CompareMappings(DNS_Mapping* prev_dm, DNS_Mapping* new_dm);
	ListVal* AddrListDelta(ListVal* al1, ListVal* al2);
	void DumpAddrList(FILE* f, ListVal* al);

	void LoadCache(FILE* f);
	void Save(FILE* f, PDict(DNS_Mapping)& m);

#ifdef HAVE_NB_DNS
	// Selects on the fd to see if there is an answer available (timeout is
	// secs). Returns 0 on timeout, -1 on EINTR, and 1 if answer is ready.
	int AnswerAvailable(int timeout);

	// Issue as many queued async requests as slots are available.
	void IssueAsyncRequests();

	// Finish the request if we have a result.  If not, time it out if
	// requested.
	void CheckAsyncAddrRequest(dns_mgr_addr_type addr, bool timeout);
	void CheckAsyncHostRequest(const char* host, bool timeout);

#endif

	// IOSource interface.
	virtual void GetFds(int* read, int* write, int* except);
	virtual double NextTimestamp(double* network_time);
	virtual void Process();
	virtual const char* Tag()	{ return "DNS_Mgr"; }

	DNS_MgrMode mode;

	PDict(ListVal) services;

	PDict(DNS_Mapping) host_mappings;
	PDict(DNS_Mapping) addr_mappings;

	DNS_mgr_request_list requests;

	nb_dns_info* nb_dns;
	char* cache_name;
	char* dir;	// directory in which cache_name resides

	int did_init;

	// DNS-related events.
	EventHandlerPtr dns_mapping_valid;
	EventHandlerPtr dns_mapping_unverified;
	EventHandlerPtr dns_mapping_new_name;
	EventHandlerPtr dns_mapping_lost_name;
	EventHandlerPtr dns_mapping_name_changed;
	EventHandlerPtr dns_mapping_altered;

	RecordType* dm_rec;

	int dns_fake_count;	// used to generate unique fake replies

	typedef list<LookupCallback*> CallbackList;

	struct AsyncRequest {
		double time;
		dns_mgr_addr_type host;
		string name;
		CallbackList callbacks;

		bool IsAddrReq() const	{ return name.length() == 0; }

		void Resolved(const char* name)
			{
			for ( CallbackList::iterator i = callbacks.begin();
			      i != callbacks.end(); ++i )
				{
				(*i)->Resolved(name);
				delete *i;
				}
			callbacks.clear();
			}

		void Resolved(TableVal* addrs)
			{
			for ( CallbackList::iterator i = callbacks.begin();
			      i != callbacks.end(); ++i )
				{
				(*i)->Resolved(addrs);
				delete *i;
				}
			callbacks.clear();
			}

		void Timeout()
			{
			for ( CallbackList::iterator i = callbacks.begin();
			      i != callbacks.end(); ++i )
				{
				(*i)->Timeout();
				delete *i;
				}
			callbacks.clear();
			}

	};

	typedef map<dns_mgr_addr_type, AsyncRequest*> AsyncRequestAddrMap;
	AsyncRequestAddrMap asyncs_addrs;

	typedef map<string, AsyncRequest*> AsyncRequestNameMap;
	AsyncRequestNameMap asyncs_names;

	typedef list<AsyncRequest*> QueuedList;
	QueuedList asyncs_queued;

	typedef priority_queue<AsyncRequest*> TimeoutQueue;
	TimeoutQueue asyncs_timeouts;

	int asyncs_pending;
};

extern DNS_Mgr* dns_mgr;

#endif
