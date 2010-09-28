// $Id: PrefixTable.cc 1016 2005-01-31 21:23:50Z vern $

#include "PrefixTable.h"

// IPv4 version.
inline static prefix_t* make_prefix(const uint32 addr, int width)
	{
	prefix_t* prefix = (prefix_t*) safe_malloc(sizeof(prefix_t));

	memcpy(&prefix->add.sin, &addr, sizeof(prefix->add.sin)) ;
	prefix->family = AF_INET;
	prefix->bitlen = width;
	prefix->ref_count = 1;

	return prefix;
	}

#ifdef BROv6
inline static prefix_t* make_prefix(const uint32* addr, int width)
	{
	prefix_t* prefix = (prefix_t*) safe_malloc(sizeof(prefix_t));

	memcpy(&prefix->add.sin6, addr, 4 * sizeof(uint32));
	prefix->family = AF_INET6;
	prefix->bitlen = width;
	prefix->ref_count = 1;

	return prefix;
	}
#endif

void* PrefixTable::Insert(const_addr_type addr, int width, void* data)
	{
	prefix_t* prefix = make_prefix(addr, width);
	patricia_node_t* node = patricia_lookup(tree, prefix);
	Deref_Prefix(prefix);

	if ( ! node )
		internal_error("Cannot create node in patricia tree");

	void* old = node->data;

	// If there is no data to be associated with addr, we take the
	// node itself.
	node->data = data ? data : node;

	return old;
	}

void* PrefixTable::Insert(const Val* value, void* data)
	{
	// [elem] -> elem
	if ( value->Type()->Tag() == TYPE_LIST &&
	     value->AsListVal()->Length() == 1 )
		value = value->AsListVal()->Index(0);

	switch ( value->Type()->Tag() ) {
	case TYPE_ADDR:
		return Insert(value->AsAddr(), NUM_ADDR_WORDS * 32, data);
		break;

	case TYPE_SUBNET:
		return Insert(value->AsSubNet()->net,
				value->AsSubNet()->width, data);
		break;

	default:
		internal_error("Wrong index type for PrefixTable");
		return 0;
	}
	}

void* PrefixTable::Lookup(const_addr_type addr, int width, bool exact) const
	{
	prefix_t* prefix = make_prefix(addr, width);
	patricia_node_t* node =
		exact ? patricia_search_exact(tree, prefix) :
			patricia_search_best(tree, prefix);

	Deref_Prefix(prefix);
	return node ? node->data : 0;
	}

void* PrefixTable::Lookup(const Val* value, bool exact) const
	{
	// [elem] -> elem
	if ( value->Type()->Tag() == TYPE_LIST &&
	     value->AsListVal()->Length() == 1 )
		value = value->AsListVal()->Index(0);

	switch ( value->Type()->Tag() ) {
	case TYPE_ADDR:
		return Lookup(value->AsAddr(), NUM_ADDR_WORDS * 32, exact);
		break;

	case TYPE_SUBNET:
		return Lookup(value->AsSubNet()->net,
				value->AsSubNet()->width, exact);
		break;

	default:
		internal_error(fmt("Wrong index type %d for PrefixTable",
					value->Type()->Tag()));
		return 0;
	}
	}

void* PrefixTable::Remove(const_addr_type addr, int width)
	{
	prefix_t* prefix = make_prefix(addr, width);
	patricia_node_t* node = patricia_search_exact(tree, prefix);
	Deref_Prefix(prefix);

	if ( ! node )
		return 0;

	void* old = node->data;
	patricia_remove(tree, node);

	return old;
	}

void* PrefixTable::Remove(const Val* value)
	{
	// [elem] -> elem
	if ( value->Type()->Tag() == TYPE_LIST &&
	     value->AsListVal()->Length() == 1 )
		value = value->AsListVal()->Index(0);

	switch ( value->Type()->Tag() ) {
	case TYPE_ADDR:
		return Remove(value->AsAddr(), NUM_ADDR_WORDS * 32);
		break;

	case TYPE_SUBNET:
		return Remove(value->AsSubNet()->net, value->AsSubNet()->width);
		break;

	default:
		internal_error("Wrong index type for PrefixTable");
		return 0;
	}
	}

PrefixTable::iterator PrefixTable::InitIterator()
	{
	iterator i;
	i.Xsp = i.Xstack;
	i.Xrn = tree->head;
	i.Xnode = 0;
	return i;
	}

void* PrefixTable::GetNext(iterator* i)
	{
	while ( 1 )
		{
		i->Xnode = i->Xrn;
		if ( ! i->Xnode )
			return 0;

		if ( i->Xrn->l )
			{
			if (i->Xrn->r)
				*i->Xsp++ = i->Xrn->r;

			i->Xrn = i->Xrn->l;
			}

		else if ( i->Xrn->r )
			i->Xrn = i->Xrn->r;

		else if (i->Xsp != i->Xstack)
			i->Xrn = *(--i->Xsp);

		else
			i->Xrn = (patricia_node_t*) 0;

		if ( i->Xnode->prefix )
			return (void*) i->Xnode->data;
		}

	// Not reached.
	}
