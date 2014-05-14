  // See the file "COPYING" in the main distribution directory for copyright.

#ifndef dnsmgr_h
#define dnsmgr_h

#include <list>
#include <map>
#include <queue>
#include <utility>

#include "util.h"
#include "BroList.h"
#include "Dict.h"
#include "EventHandler.h"
#include "IOSource.h"
#include "IPAddr.h"

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

enum DNS_MgrMode {
	DNS_PRIME,	// used to prime the cache
	DNS_FORCE,	// internal error if cache miss
	DNS_DEFAULT,	// lookup names as they're requested
	DNS_FAKE,	// don't look up names, just return dummy results
};

// Number of seconds we'll wait for a reply.
#define DNS_TIMEOUT 5

class DNS_Mgr : public IOSource {
public:
	DNS_Mgr(DNS_MgrMode mode);
	virtual ~DNS_Mgr();

	bool Init();
	void Flush();

	// Looks up the address or addresses of the given host, and returns
	// a set of addr.
	TableVal* LookupHost(const char* host);

	Val* LookupAddr(const IPAddr& addr);

	// Define the directory where to store the data.
	void SetDir(const char* arg_dir)	{ dir = copy_string(arg_dir); }

	void Verify();
	void Resolve();
	int Save();

	const char* LookupAddrInCache(const IPAddr& addr);
	TableVal* LookupNameInCache(const string& name);
	const char* LookupTextInCache(const string& name);

	// Support for async lookups.
	class LookupCallback {
	public:
		LookupCallback()	{ }
		virtual ~LookupCallback()	{ }

		virtual void Resolved(const char* name)	{ };
		virtual void Resolved(TableVal* addrs)	{ };
		virtual void Timeout() = 0;
	};

	void AsyncLookupAddr(const IPAddr& host, LookupCallback* callback);
	void AsyncLookupName(const string& name, LookupCallback* callback);
	void AsyncLookupNameText(const string& name, LookupCallback* callback);

	struct Stats {
		unsigned long requests;	// These count only async requests.
		unsigned long successful;
		unsigned long failed;
		unsigned long pending;
		unsigned long cached_hosts;
		unsigned long cached_addresses;
		unsigned long cached_texts;
	};

	void GetStats(Stats* stats);

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

	typedef map<string, pair<DNS_Mapping*, DNS_Mapping*> > HostMap;
	typedef map<IPAddr, DNS_Mapping*> AddrMap;
	typedef map<string, DNS_Mapping*> TextMap;
	void LoadCache(FILE* f);
	void Save(FILE* f, const AddrMap& m);
	void Save(FILE* f, const HostMap& m);

	// Selects on the fd to see if there is an answer available (timeout
	// is secs). Returns 0 on timeout, -1 on EINTR or other error, and 1
	// if answer is ready.
	int AnswerAvailable(int timeout);

	// Issue as many queued async requests as slots are available.
	void IssueAsyncRequests();

	// Finish the request if we have a result.  If not, time it out if
	// requested.
	void CheckAsyncAddrRequest(const IPAddr& addr, bool timeout);
	void CheckAsyncHostRequest(const char* host, bool timeout);
	void CheckAsyncTextRequest(const char* host, bool timeout);

	// Process outstanding requests.
	void DoProcess(bool flush);

	// IOSource interface.
	virtual void GetFds(int* read, int* write, int* except);
	virtual double NextTimestamp(double* network_time);
	virtual void Process();
	virtual const char* Tag()	{ return "DNS_Mgr"; }

	DNS_MgrMode mode;

	PDict(ListVal) services;

	HostMap host_mappings;
	AddrMap addr_mappings;
	TextMap text_mappings;

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

	typedef list<LookupCallback*> CallbackList;

	struct AsyncRequest {
		double time;
		IPAddr host;
		string name;
		bool is_txt;
		CallbackList callbacks;

		AsyncRequest() : time(0.0), is_txt(false) { }

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

	typedef map<IPAddr, AsyncRequest*> AsyncRequestAddrMap;
	AsyncRequestAddrMap asyncs_addrs;

	typedef map<string, AsyncRequest*> AsyncRequestNameMap;
	AsyncRequestNameMap asyncs_names;

	typedef map<string, AsyncRequest*> AsyncRequestTextMap;
	AsyncRequestTextMap asyncs_texts;

	typedef list<AsyncRequest*> QueuedList;
	QueuedList asyncs_queued;

	typedef priority_queue<AsyncRequest*> TimeoutQueue;
	TimeoutQueue asyncs_timeouts;

	int asyncs_pending;

	unsigned long num_requests;
	unsigned long successful;
	unsigned long failed;
};

extern DNS_Mgr* dns_mgr;

#endif
