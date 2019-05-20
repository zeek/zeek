// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"

#include <stdlib.h>

#include "Obj.h"
#include "Serializer.h"
#include "Func.h"
#include "File.h"
#include "plugin/Manager.h"

Location no_location("<no location>", 0, 0, 0, 0);
Location start_location("<start uninitialized>", 0, 0, 0, 0);
Location end_location("<end uninitialized>", 0, 0, 0, 0);

bool Location::Serialize(SerialInfo* info) const
	{
	return SerialObj::Serialize(info);
	}

Location* Location::Unserialize(UnserialInfo* info)
	{
	return (Location*) SerialObj::Unserialize(info, SER_LOCATION);
	}

IMPLEMENT_SERIAL(Location, SER_LOCATION);

bool Location::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_LOCATION, SerialObj);
	info->s->WriteOpenTag("Location");

	if ( ! (SERIALIZE(filename) &&
	        SERIALIZE(first_line) &&
	        SERIALIZE(last_line) &&
	        SERIALIZE(first_column) &&
	        SERIALIZE(last_column)) )
		return false;

	info->s->WriteCloseTag("Location");
	return true;
	}

bool Location::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(SerialObj);

	delete_data = true;

	return UNSERIALIZE_STR(&filename, 0)
		&& UNSERIALIZE(&first_line)
		&& UNSERIALIZE(&last_line)
		&& UNSERIALIZE(&first_column)
		&& UNSERIALIZE(&last_column);
	}

void Location::Describe(ODesc* d) const
	{
	if ( filename )
		{
		d->Add(filename);

		if ( first_line == 0 )
			return;

		d->AddSP(",");
		}

	if ( last_line != first_line )
		{
		d->Add("lines ");
		d->Add(first_line);
		d->Add("-");
		d->Add(last_line);
		}
	else
		{
		d->Add("line ");
		d->Add(first_line);
		}
	}

bool Location::operator==(const Location& l) const
	{
	if ( filename == l.filename ||
	     (filename && l.filename && streq(filename, l.filename)) )
		return first_line == l.first_line && last_line == l.last_line;
	else
		return false;
	}

int BroObj::suppress_errors = 0;

BroObj::~BroObj()
	{
	if ( notify_plugins )
		PLUGIN_HOOK_VOID(HOOK_BRO_OBJ_DTOR, HookBroObjDtor(this));

	delete location;
	}

void BroObj::Warn(const char* msg, const BroObj* obj2, int pinpoint_only) const
	{
	ODesc d;
	DoMsg(&d, msg, obj2, pinpoint_only);
	reporter->Warning("%s", d.Description());
	reporter->PopLocation();
	}

void BroObj::Error(const char* msg, const BroObj* obj2, int pinpoint_only) const
	{
	if ( suppress_errors )
		return;

	ODesc d;
	DoMsg(&d, msg, obj2, pinpoint_only);
	reporter->Error("%s", d.Description());
	reporter->PopLocation();
	}

void BroObj::BadTag(const char* msg, const char* t1, const char* t2) const
	{
	char out[512];

	if ( t2 )
		snprintf(out, sizeof(out), "%s (%s/%s)", msg, t1, t2);
	else if ( t1 )
		snprintf(out, sizeof(out), "%s (%s)", msg, t1);
	else
		snprintf(out, sizeof(out), "%s", msg);

	ODesc d;
	DoMsg(&d, out);
	reporter->FatalError("%s", d.Description());
	reporter->PopLocation();
	}

void BroObj::Internal(const char* msg) const
	{
	ODesc d;
	DoMsg(&d, msg);
	auto rcs = render_call_stack();

	if ( rcs.empty() )
		reporter->InternalError("%s", d.Description());
	else
		reporter->InternalError("%s, call stack: %s", d.Description(), rcs.data());

	reporter->PopLocation();
	}

void BroObj::InternalWarning(const char* msg) const
	{
	ODesc d;
	DoMsg(&d, msg);
	reporter->InternalWarning("%s", d.Description());
	reporter->PopLocation();
	}

void BroObj::AddLocation(ODesc* d) const
	{
	if ( ! location )
		{
		d->Add("<no location>");
		return;
		}

	location->Describe(d);
	}

bool BroObj::SetLocationInfo(const Location* start, const Location* end)
	{
	if ( ! start || ! end )
		return false;

	if ( end->filename && ! streq(start->filename, end->filename) )
		return false;

	if ( location && (start == &no_location || end == &no_location) )
		// We already have a better location, so don't use this one.
		return true;

	delete location;

	location = new Location(start->filename,
				start->first_line, end->last_line,
				start->first_column, end->last_column);

	return true;
	}

void BroObj::UpdateLocationEndInfo(const Location& end)
	{
	if ( ! location )
		SetLocationInfo(&end, &end);

	location->last_line = end.last_line;
	location->last_column = end.last_column;
	}

void BroObj::DoMsg(ODesc* d, const char s1[], const BroObj* obj2,
			int pinpoint_only) const
	{
	d->SetShort();

	d->Add(s1);
	PinPoint(d, obj2, pinpoint_only);

	const Location* loc2 = 0;
	if ( obj2 && obj2->GetLocationInfo() != &no_location &&
		 *obj2->GetLocationInfo() != *GetLocationInfo() )
		loc2 = obj2->GetLocationInfo();

	reporter->PushLocation(GetLocationInfo(), loc2);
	}

void BroObj::PinPoint(ODesc* d, const BroObj* obj2, int pinpoint_only) const
	{
	d->Add(" (");
	Describe(d);
	if ( obj2 && ! pinpoint_only )
		{
		d->Add(" and ");
		obj2->Describe(d);
		}

	d->Add(")");
	}

bool BroObj::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_BRO_OBJ, SerialObj);

	info->s->WriteOpenTag("Object");

	Location* loc = info->include_locations ? location : 0;
	SERIALIZE_OPTIONAL(loc);
	info->s->WriteCloseTag("Object");

	return true;
	}

bool BroObj::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(SerialObj);

	delete location;

	UNSERIALIZE_OPTIONAL(location, Location::Unserialize(info));
	return true;
	}

void print(const BroObj* obj)
	{
	static BroFile fstderr(stderr);
	ODesc d(DESC_READABLE, &fstderr);
	obj->Describe(&d);
	d.Add("\n");
	}

void bad_ref(int type)
	{
	reporter->InternalError("bad reference count [%d]", type);
	abort();
	}

void bro_obj_delete_func(void* v)
	{
	Unref((BroObj*) v);
	}
