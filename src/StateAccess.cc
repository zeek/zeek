#include "Val.h"
#include "StateAccess.h"
#include "Event.h"
#include "NetVar.h"
#include "DebugLogger.h"

NotifierRegistry notifiers;

NotifierRegistry::~NotifierRegistry()
	{
	for ( auto i : ids )
		Unref(i.first);

	for ( auto i : vals )
		Unref(i.first);
	}

void NotifierRegistry::Register(ID* id, NotifierRegistry::Notifier* notifier)
	{
	DBG_LOG(DBG_NOTIFIERS, "registering ID %s for notifier %s",
		id->Name(), notifier->Name());

	Attr* attr = new Attr(ATTR_TRACKED);

	if ( id->Attrs() )
		{
		if ( ! id->Attrs()->FindAttr(ATTR_TRACKED) )
			id->Attrs()->AddAttr(attr);
		}
	else
		{
		attr_list* a = new attr_list{attr};
		id->SetAttrs(new Attributes(a, id->Type(), false));
		}

	Unref(attr);

	ids.insert({id, notifier});
	Ref(id);
	}

void NotifierRegistry::Register(Val* val, NotifierRegistry::Notifier* notifier)
	{
	if ( ! val->IsMutableVal() )
		return;

	DBG_LOG(DBG_NOTIFIERS, "registering value %p for notifier %s",
		val, notifier->Name());

	vals.insert({val, notifier});
	Ref(val);
	}

void NotifierRegistry::Unregister(ID* id, NotifierRegistry::Notifier* notifier)
	{
	DBG_LOG(DBG_NOTIFIERS, "unregistering ID %s for notifier %s",
		id->Name(), notifier->Name());

	auto x = ids.equal_range(id);
	for ( auto i = x.first; i != x.second; i++ )
		{
		if ( i->second == notifier )
			{
			ids.erase(i);
			Unref(id);
			break;
			}
		}

	if ( ids.find(id) == ids.end() )
		// Last registered notifier for this ID
		id->Attrs()->RemoveAttr(ATTR_TRACKED);
	}

void NotifierRegistry::Unregister(Val* val, NotifierRegistry::Notifier* notifier)
	{
	DBG_LOG(DBG_NOTIFIERS, "unregistering Val %p for notifier %s",
		val, notifier->Name());

	auto x = vals.equal_range(val);
	for ( auto i = x.first; i != x.second; i++ )
		{
		if ( i->second == notifier )
			{
			vals.erase(i);
			Unref(val);
			break;
			}
		}
	}

void NotifierRegistry::Modified(Val *val)
	{
	DBG_LOG(DBG_NOTIFIERS, "modification to tracked value %p", val);

	auto x = vals.equal_range(val);
	for ( auto i = x.first; i != x.second; i++ )
		i->second->Modified(val);
	}

void NotifierRegistry::Modified(ID *id)
	{
	DBG_LOG(DBG_NOTIFIERS, "modification to tracked ID %s", id->Name());

	auto x = ids.equal_range(id);
	for ( auto i = x.first; i != x.second; i++ )
		i->second->Modified(id);
	}

const char* NotifierRegistry::Notifier::Name() const
	{
	return fmt("%p", this);
	}

