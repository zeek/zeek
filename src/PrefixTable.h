#pragma once

extern "C" {
	#include "zeek/patricia.h"
}

#include <list>

#include "zeek/IPAddr.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(Val, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(SubNetVal, zeek);

namespace zeek::detail {

class PrefixTable {
private:
	struct iterator {
		patricia_node_t* Xstack[PATRICIA_MAXBITS+1];
		patricia_node_t** Xsp;
		patricia_node_t* Xrn;
		patricia_node_t* Xnode;
	};

public:
	PrefixTable()	{ tree = New_Patricia(128); delete_function = nullptr; }
	~PrefixTable()	{ Destroy_Patricia(tree, delete_function); }

	// Addr in network byte order. If data is zero, acts like a set.
	// Returns ptr to old data if already existing.
	// For existing items without data, returns non-nil if found.
	void* Insert(const IPAddr& addr, int width, void* data = nullptr);

	// Value may be addr or subnet.
	void* Insert(const Val* value, void* data = nullptr);

	// Returns nil if not found, pointer to data otherwise.
	// For items without data, returns non-nil if found.
	// If exact is false, performs exact rather than longest-prefix match.
	void* Lookup(const IPAddr& addr, int width, bool exact = false) const;
	void* Lookup(const Val* value, bool exact = false) const;

	// Returns list of all found matches or empty list otherwise.
	std::list<std::tuple<IPPrefix, void*>> FindAll(const IPAddr& addr, int width) const;
	std::list<std::tuple<IPPrefix, void*>> FindAll(const SubNetVal* value) const;

	// Returns pointer to data or nil if not found.
	void* Remove(const IPAddr& addr, int width);
	void* Remove(const Val* value);

	void Clear()	{ Clear_Patricia(tree, delete_function); }

	// Sets a function to call for each node when table is cleared/destroyed.
	void SetDeleteFunction(data_fn_t del_fn)	{ delete_function = del_fn; }

	iterator InitIterator();
	void* GetNext(iterator* i);

private:
	static prefix_t* MakePrefix(const IPAddr& addr, int width);
	static IPPrefix PrefixToIPPrefix(prefix_t* p);

	patricia_tree_t* tree;
	data_fn_t delete_function;
};

} // namespace zeek::detail
