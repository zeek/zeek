#include "zeek/Anon.h"

#include <sys/time.h>
#include <unistd.h>
#include <cassert>
#include <cstdlib>

#include "zeek/Event.h"
#include "zeek/ID.h"
#include "zeek/IPAddr.h"
#include "zeek/NetVar.h"
#include "zeek/Reporter.h"
#include "zeek/Scope.h"
#include "zeek/Val.h"
#include "zeek/net_util.h"
#include "zeek/util.h"

namespace zeek::detail
	{

AnonymizeIPAddr* ip_anonymizer[NUM_ADDR_ANONYMIZATION_METHODS] = {nullptr};

static uint32_t rand32()
	{
	return ((util::detail::random_number() & 0xffff) << 16) |
	       (util::detail::random_number() & 0xffff);
	}

// From tcpdpriv.
static int bi_ffs(uint32_t value)
	{
	int add = 0;
	static uint8_t bvals[] = {0, 4, 3, 3, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1};

	if ( (value & 0xFFFF0000) == 0 )
		{
		if ( value == 0 )
			// Zero input ==> zero output.
			return 0;

		add += 16;
		}

	else
		value >>= 16;

	if ( (value & 0xFF00) == 0 )
		add += 8;
	else
		value >>= 8;

	if ( (value & 0xF0) == 0 )
		add += 4;
	else
		value >>= 4;

	return add + bvals[value & 0xf];
	}

#define first_n_bit_mask(n) (~(0xFFFFFFFFU >> n))

ipaddr32_t AnonymizeIPAddr::Anonymize(ipaddr32_t addr)
	{
	std::map<ipaddr32_t, ipaddr32_t>::iterator p = mapping.find(addr);
	if ( p != mapping.end() )
		return p->second;
	else
		{
		ipaddr32_t new_addr = anonymize(addr);
		mapping[addr] = new_addr;

		return new_addr;
		}
	}

// Keep the specified prefix unchanged.
bool AnonymizeIPAddr::PreservePrefix(ipaddr32_t /* input */, int /* num_bits */)
	{
	reporter->InternalError("prefix preserving is not supported for the anonymizer");
	return false;
	}

bool AnonymizeIPAddr::PreserveNet(ipaddr32_t input)
	{
	switch ( addr_to_class(ntohl(input)) )
		{
		case 'A':
			return PreservePrefix(input, 8);
		case 'B':
			return PreservePrefix(input, 16);
		case 'C':
			return PreservePrefix(input, 24);
		default:
			return false;
		}
	}

ipaddr32_t AnonymizeIPAddr_Seq::anonymize(ipaddr32_t /* input */)
	{
	++seq;
	return htonl(seq);
	}

ipaddr32_t AnonymizeIPAddr_RandomMD5::anonymize(ipaddr32_t input)
	{
	uint8_t digest[16];
	ipaddr32_t output = 0;

	util::detail::hmac_md5(sizeof(input), (u_char*)(&input), digest);

	for ( int i = 0; i < 4; ++i )
		output = (output << 8) | digest[i];

	return output;
	}

// This code is from "On the Design and Performance of Prefix-Preserving
// IP Traffic Trace Anonymization", by Xu et al (IMW 2001)
//
// http://www.imconf.net/imw-2001/proceedings.html

ipaddr32_t AnonymizeIPAddr_PrefixMD5::anonymize(ipaddr32_t input)
	{
	uint8_t digest[16];
	ipaddr32_t prefix_mask = 0xffffffff;
	input = ntohl(input);
	ipaddr32_t output = input;

	for ( int i = 0; i < 32; ++i )
		{
		// PAD(x_0 ... x_{i-1}) = x_0 ... x_{i-1} 1 0 ... 0 .
		prefix.len = htonl(i + 1);
		prefix.prefix = htonl((input & ~(prefix_mask >> i)) | (1 << (31 - i)));

		// HK(PAD(x_0 ... x_{i-1})).
		util::detail::hmac_md5(sizeof(prefix), (u_char*)&prefix, digest);

		// f_{i-1} = LSB(HK(PAD(x_0 ... x_{i-1}))).
		ipaddr32_t bit_mask = (digest[0] & 1) << (31 - i);

		// x_i' = x_i ^ f_{i-1}.
		output ^= bit_mask;
		}

	return htonl(output);
	}

AnonymizeIPAddr_A50::~AnonymizeIPAddr_A50()
	{
	for ( auto& b : blocks )
		delete[] b;
	}

void AnonymizeIPAddr_A50::init()
	{
	root = next_free_node = nullptr;

	// Prepare special nodes for 0.0.0.0 and 255.255.255.255.
	memset(&special_nodes[0], 0, sizeof(special_nodes));
	special_nodes[0].input = special_nodes[0].output = 0;
	special_nodes[1].input = special_nodes[1].output = 0xFFFFFFFF;

	method = 0;
	before_anonymization = 1;
	new_mapping = 0;
	}

bool AnonymizeIPAddr_A50::PreservePrefix(ipaddr32_t input, int num_bits)
	{
	DEBUG_MSG("%s/%d\n", IPAddr(IPv4, &input, IPAddr::Network).AsString().c_str(), num_bits);

	if ( ! before_anonymization )
		{
		reporter->Error("prefix preservation specified after anonymization begun");
		return false;
		}

	input = ntohl(input);

	// Sanitize input.
	input = input & first_n_bit_mask(num_bits);

	Node* n = find_node(input);

	// Preserve the first num_bits bits of addr.
	if ( num_bits == 32 )
		n->output = input;

	else if ( num_bits > 0 )
		{
		assert((0xFFFFFFFFU >> 1) == 0x7FFFFFFFU);
		uint32_t suffix_mask = (0xFFFFFFFFU >> num_bits);
		uint32_t prefix_mask = ~suffix_mask;
		n->output = (input & prefix_mask) | (rand32() & suffix_mask);
		}

	return true;
	}

ipaddr32_t AnonymizeIPAddr_A50::anonymize(ipaddr32_t a)
	{
	before_anonymization = 0;
	new_mapping = 0;

	if ( Node* n = find_node(ntohl(a)) )
		{
		ipaddr32_t output = htonl(n->output);
		return output;
		}
	else
		return 0;
	}

AnonymizeIPAddr_A50::Node* AnonymizeIPAddr_A50::new_node_block()
	{
	assert(! next_free_node);

	int block_size = 1024;
	Node* block = new Node[block_size];
	if ( ! block )
		reporter->InternalError("out of memory!");

	blocks.push_back(block);

	for ( int i = 1; i < block_size - 1; ++i )
		block[i].child[0] = &block[i + 1];

	block[block_size - 1].child[0] = nullptr;
	next_free_node = &block[1];

	return &block[0];
	}

inline AnonymizeIPAddr_A50::Node* AnonymizeIPAddr_A50::new_node()
	{
	new_mapping = 1;

	if ( next_free_node )
		{
		Node* n = next_free_node;
		next_free_node = n->child[0];
		return n;
		}
	else
		return new_node_block();
	}

inline void AnonymizeIPAddr_A50::free_node(Node* n)
	{
	n->child[0] = next_free_node;
	next_free_node = n;
	}

ipaddr32_t AnonymizeIPAddr_A50::make_output(ipaddr32_t old_output, int swivel) const
	{
	// -A50 anonymization
	if ( swivel == 32 )
		return old_output ^ 1;
	else
		{
		// Bits up to swivel are unchanged; bit swivel is flipped.
		ipaddr32_t known_part = ((old_output >> (32 - swivel)) ^ 1) << (32 - swivel);

		// Remainder of bits are random.
		return known_part | ((rand32() & 0x7FFFFFFF) >> swivel);
		}
	}

AnonymizeIPAddr_A50::Node* AnonymizeIPAddr_A50::make_peer(ipaddr32_t a, Node* n)
	{
	if ( a == 0 || a == 0xFFFFFFFFU )
		reporter->InternalError("0.0.0.0 and 255.255.255.255 should never get into the tree");

	// Become a peer.
	// Algorithm: create two nodes, the two peers.  Leave orig node as
	// the parent of the two new ones.

	Node* down[2];

	if ( ! (down[0] = new_node()) )
		return nullptr;

	if ( ! (down[1] = new_node()) )
		{
		free_node(down[0]);
		return nullptr;
		}

	// swivel is first bit 'a' and 'old->input' differ.
	int swivel = bi_ffs(a ^ n->input);

	// bitvalue is the value of that bit of 'a'.
	int bitvalue = (a >> (32 - swivel)) & 1;

	down[bitvalue]->input = a;
	down[bitvalue]->output = make_output(n->output, swivel);
	down[bitvalue]->child[0] = down[bitvalue]->child[1] = nullptr;

	*down[1 - bitvalue] = *n; // copy orig node down one level

	n->input = down[1]->input; // NB: 1s to the right (0s to the left)
	n->output = down[1]->output;
	n->child[0] = down[0]; // point to children
	n->child[1] = down[1];

	return down[bitvalue];
	}

AnonymizeIPAddr_A50::Node* AnonymizeIPAddr_A50::find_node(ipaddr32_t a)
	{
	// Watch out for special IP addresses, which never make it
	// into the tree.
	if ( a == 0 || a == 0xFFFFFFFFU )
		return &special_nodes[a & 1];

	if ( ! root )
		{
		root = new_node();
		root->input = a;
		root->output = rand32();
		root->child[0] = root->child[1] = nullptr;

		return root;
		}

	// Straight from tcpdpriv.
	Node* n = root;
	while ( n )
		{
		if ( n->input == a )
			return n;

		if ( ! n->child[0] )
			n = make_peer(a, n);

		else
			{
			// swivel is the first bit in which the two children
			// differ.
			int swivel = bi_ffs(n->child[0]->input ^ n->child[1]->input);

			if ( bi_ffs(a ^ n->input) < swivel )
				// Input differs earlier.
				n = make_peer(a, n);

			else if ( a & (1 << (32 - swivel)) )
				n = n->child[1];

			else
				n = n->child[0];
			}
		}

	reporter->InternalError("out of memory!");
	return nullptr;
	}

static TableValPtr anon_preserve_orig_addr;
static TableValPtr anon_preserve_resp_addr;
static TableValPtr anon_preserve_other_addr;

void init_ip_addr_anonymizers()
	{
	ip_anonymizer[KEEP_ORIG_ADDR] = nullptr;
	ip_anonymizer[SEQUENTIALLY_NUMBERED] = new AnonymizeIPAddr_Seq();
	ip_anonymizer[RANDOM_MD5] = new AnonymizeIPAddr_RandomMD5();
	ip_anonymizer[PREFIX_PRESERVING_A50] = new AnonymizeIPAddr_A50();
	ip_anonymizer[PREFIX_PRESERVING_MD5] = new AnonymizeIPAddr_PrefixMD5();

	auto id = global_scope()->Find("preserve_orig_addr");

	if ( id )
		anon_preserve_orig_addr = cast_intrusive<TableVal>(id->GetVal());

	id = global_scope()->Find("preserve_resp_addr");

	if ( id )
		anon_preserve_resp_addr = cast_intrusive<TableVal>(id->GetVal());

	id = global_scope()->Find("preserve_other_addr");

	if ( id )
		anon_preserve_other_addr = cast_intrusive<TableVal>(id->GetVal());
	}

ipaddr32_t anonymize_ip(ipaddr32_t ip, enum ip_addr_anonymization_class_t cl)
	{
	TableVal* preserve_addr = nullptr;
	auto addr = make_intrusive<AddrVal>(ip);

	int method = -1;

	switch ( cl )
		{
		case ORIG_ADDR: // client address
			preserve_addr = anon_preserve_orig_addr.get();
			method = orig_addr_anonymization;
			break;

		case RESP_ADDR: // server address
			preserve_addr = anon_preserve_resp_addr.get();
			method = resp_addr_anonymization;
			break;

		default:
			preserve_addr = anon_preserve_other_addr.get();
			method = other_addr_anonymization;
			break;
		}

	ipaddr32_t new_ip = 0;

	if ( preserve_addr && preserve_addr->FindOrDefault(addr) )
		new_ip = ip;

	else if ( method >= 0 && method < NUM_ADDR_ANONYMIZATION_METHODS )
		{
		if ( method == KEEP_ORIG_ADDR )
			new_ip = ip;

		else if ( ! ip_anonymizer[method] )
			reporter->InternalError("IP anonymizer not initialized");

		else
			new_ip = ip_anonymizer[method]->Anonymize(ip);
		}

	else
		reporter->InternalError("invalid IP anonymization method");

#ifdef LOG_ANONYMIZATION_MAPPING
	log_anonymization_mapping(ip, new_ip);
#endif
	return new_ip;
	}

#ifdef LOG_ANONYMIZATION_MAPPING

void log_anonymization_mapping(ipaddr32_t input, ipaddr32_t output)
	{
	if ( anonymization_mapping )
		event_mgr.Enqueue(anonymization_mapping, make_intrusive<AddrVal>(input),
		                  make_intrusive<AddrVal>(output));
	}

#endif

	} // namespace zeek::detail
