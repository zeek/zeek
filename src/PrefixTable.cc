#include "PrefixTable.h"
#include "Reporter.h"
#include "Val.h"

prefix_t* PrefixTable::MakePrefix(const IPAddr& addr, int width)
	{
	prefix_t* prefix = (prefix_t*) safe_malloc(sizeof(prefix_t));

	addr.CopyIPv6(&prefix->add.sin6);
	prefix->family = AF_INET6;
	prefix->bitlen = width;
	prefix->ref_count = 1;

	return prefix;
	}

IPPrefix PrefixTable::PrefixToIPPrefix(prefix_t* prefix)
	{
	return IPPrefix(IPAddr(IPv6, reinterpret_cast<const uint32_t*>(&prefix->add.sin6), IPAddr::Network), prefix->bitlen, true);
	}

void* PrefixTable::Insert(const IPAddr& addr, int width, void* data)
	{
	prefix_t* prefix = MakePrefix(addr, width);
	patricia_node_t* node = patricia_lookup(tree, prefix);
	Deref_Prefix(prefix);

	if ( ! node )
		{
		reporter->InternalWarning("Cannot create node in patricia tree");
		return nullptr;
		}

	void* old = node->data;

	// If there is no data to be associated with addr, we take the
	// node itself.
	node->data = data ? data : node;

	return old;
	}

void* PrefixTable::Insert(const Val* value, void* data)
	{
	// [elem] -> elem
	if ( value->GetType()->Tag() == TYPE_LIST &&
	     value->AsListVal()->Length() == 1 )
		value = value->AsListVal()->Idx(0).get();

	switch ( value->GetType()->Tag() ) {
	case TYPE_ADDR:
		return Insert(value->AsAddr(), 128, data);
		break;

	case TYPE_SUBNET:
		return Insert(value->AsSubNet().Prefix(),
				value->AsSubNet().LengthIPv6(), data);
		break;

	default:
		reporter->InternalWarning("Wrong index type for PrefixTable");
		return nullptr;
	}
	}

std::list<std::tuple<IPPrefix,void*>> PrefixTable::FindAll(const IPAddr& addr, int width) const
	{
	std::list<std::tuple<IPPrefix,void*>> out;
	prefix_t* prefix = MakePrefix(addr, width);

	int elems = 0;
	patricia_node_t** list = nullptr;

	patricia_search_all(tree, prefix, &list, &elems);

	for ( int i = 0; i < elems; ++i )
		out.push_back(std::make_tuple(PrefixToIPPrefix(list[i]->prefix), list[i]->data));

	Deref_Prefix(prefix);
	free(list);
	return out;
	}

std::list<std::tuple<IPPrefix,void*>> PrefixTable::FindAll(const SubNetVal* value) const
	{
	return FindAll(value->AsSubNet().Prefix(), value->AsSubNet().LengthIPv6());
	}

void* PrefixTable::Lookup(const IPAddr& addr, int width, bool exact) const
	{
	prefix_t* prefix = MakePrefix(addr, width);
	patricia_node_t* node =
		exact ? patricia_search_exact(tree, prefix) :
			patricia_search_best(tree, prefix);

	int elems = 0;
	patricia_node_t** list = nullptr;

	Deref_Prefix(prefix);
	return node ? node->data : nullptr;
	}

void* PrefixTable::Lookup(const Val* value, bool exact) const
	{
	// [elem] -> elem
	if ( value->GetType()->Tag() == TYPE_LIST &&
	     value->AsListVal()->Length() == 1 )
		value = value->AsListVal()->Idx(0).get();

	switch ( value->GetType()->Tag() ) {
	case TYPE_ADDR:
		return Lookup(value->AsAddr(), 128, exact);
		break;

	case TYPE_SUBNET:
		return Lookup(value->AsSubNet().Prefix(),
				value->AsSubNet().LengthIPv6(), exact);
		break;

	default:
		reporter->InternalWarning("Wrong index type %d for PrefixTable",
		                          value->GetType()->Tag());
		return nullptr;
	}
	}

void* PrefixTable::Remove(const IPAddr& addr, int width)
	{
	prefix_t* prefix = MakePrefix(addr, width);
	patricia_node_t* node = patricia_search_exact(tree, prefix);
	Deref_Prefix(prefix);

	if ( ! node )
		return nullptr;

	void* old = node->data;
	patricia_remove(tree, node);

	return old;
	}

void* PrefixTable::Remove(const Val* value)
	{
	// [elem] -> elem
	if ( value->GetType()->Tag() == TYPE_LIST &&
	     value->AsListVal()->Length() == 1 )
		value = value->AsListVal()->Idx(0).get();

	switch ( value->GetType()->Tag() ) {
	case TYPE_ADDR:
		return Remove(value->AsAddr(), 128);
		break;

	case TYPE_SUBNET:
		return Remove(value->AsSubNet().Prefix(),
				value->AsSubNet().LengthIPv6());
		break;

	default:
		reporter->InternalWarning("Wrong index type for PrefixTable");
		return nullptr;
	}
	}

PrefixTable::iterator PrefixTable::InitIterator()
	{
	iterator i;
	i.Xsp = i.Xstack;
	i.Xrn = tree->head;
	i.Xnode = nullptr;
	return i;
	}

void* PrefixTable::GetNext(iterator* i)
	{
	while ( true )
		{
		i->Xnode = i->Xrn;
		if ( ! i->Xnode )
			return nullptr;

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
			i->Xrn = (patricia_node_t*) nullptr;

		if ( i->Xnode->prefix )
			return (void*) i->Xnode->data;
		}

	// Not reached.
	}
