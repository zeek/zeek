// The prefix-preserving IP address anonymization code is largely
// based on (and sometimes directly copied from) Eddie Kohler's
// ipsumdump-1.20 code, per:
//
//	http://www.icir.org/kohler/ipsumdump/
//
// ipsumdump, in turn, takes some of its code from tcpdpriv:
//
//	http://ita.ee.lbl.gov/html/contrib/tcpdpriv.html

#ifndef anon_h
#define anon_h

#include <vector>
#include <set>
#include <map>
using namespace std;

#include "Reporter.h"
#include "net_util.h"

// TODO: Anon.h may not be the right place to put these functions ...

enum ip_addr_anonymization_class_t {
	ORIG_ADDR,	// client address
	RESP_ADDR,	// server address
	OTHER_ADDR,
	NUM_ADDR_ANONYMIZATION_CLASSES,
};

enum ip_addr_anonymization_method_t {
	KEEP_ORIG_ADDR,
	SEQUENTIALLY_NUMBERED,
	RANDOM_MD5,
	PREFIX_PRESERVING_A50,
	PREFIX_PRESERVING_MD5,
	NUM_ADDR_ANONYMIZATION_METHODS,
};

typedef uint32 ipaddr32_t;

// NOTE: all addresses in parameters of *public* functions are in
// network order.

class AnonymizeIPAddr {
public:
	virtual ~AnonymizeIPAddr()	{ mapping.clear(); }

	ipaddr32_t Anonymize(ipaddr32_t addr);

	// Keep the specified prefix unchanged.
	virtual int PreservePrefix(ipaddr32_t /* input */, int /* num_bits */)
		{
		reporter->InternalError("prefix preserving is not supported for the anonymizer");
		return 0;
		}

	virtual ipaddr32_t anonymize(ipaddr32_t addr) = 0;
	
	int PreserveNet(ipaddr32_t input);

protected:
	map<ipaddr32_t, ipaddr32_t> mapping;
};

class AnonymizeIPAddr_Seq : public AnonymizeIPAddr {
public:
	AnonymizeIPAddr_Seq()	{ seq = 1; }
	ipaddr32_t anonymize(ipaddr32_t addr);

protected:
	ipaddr32_t seq;
};

class AnonymizeIPAddr_RandomMD5 : public AnonymizeIPAddr {
public:
	ipaddr32_t anonymize(ipaddr32_t addr);
};

class AnonymizeIPAddr_PrefixMD5 : public AnonymizeIPAddr {
public:
	ipaddr32_t anonymize(ipaddr32_t addr);

protected:
	struct anon_prefix {
		int len;
		ipaddr32_t prefix;
	} prefix;
};

class AnonymizeIPAddr_A50 : public AnonymizeIPAddr {
public:
	AnonymizeIPAddr_A50()	{ init(); }
	~AnonymizeIPAddr_A50();

	ipaddr32_t anonymize(ipaddr32_t addr);
	int PreservePrefix(ipaddr32_t input, int num_bits);

protected:
	struct Node {
		ipaddr32_t input;
		ipaddr32_t output;
		Node* child[2];
	};

	int method;
	int before_anonymization;
	int new_mapping;

	// The root of prefix preserving mapping tree.
	Node* root;

	// A node pool for new_node.
	Node* next_free_node;
	std::vector<Node*> blocks;

	// for 0.0.0.0 and 255.255.255.255.
	Node special_nodes[2];

	void init();

	Node* new_node();
	Node* new_node_block();
	void free_node(Node*);

	ipaddr32_t make_output(ipaddr32_t, int) const;
	Node* make_peer(ipaddr32_t, Node*);
	Node* find_node(ipaddr32_t);
};

// The global IP anonymizers.
extern AnonymizeIPAddr* ip_anonymizer[NUM_ADDR_ANONYMIZATION_METHODS];

void init_ip_addr_anonymizers();
ipaddr32_t anonymize_ip(ipaddr32_t ip, enum ip_addr_anonymization_class_t cl);

#define LOG_ANONYMIZATION_MAPPING
void log_anonymization_mapping(ipaddr32_t input, ipaddr32_t output);

#endif
