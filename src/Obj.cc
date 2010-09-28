// $Id: Obj.cc 6752 2009-06-14 04:24:52Z vern $
//
// See the file "COPYING" in the main distribution directory for copyright.

#include "config.h"

#include <stdlib.h>

#include "Obj.h"
#include "Serializer.h"
#include "File.h"

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
	SERIALIZE(filename);
	SERIALIZE(first_line);
	SERIALIZE(last_line);
	SERIALIZE(first_column);
	SERIALIZE(last_column);
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

bool Location::operator==(const Location& l) const
	{
	if ( filename == l.filename ||
	     (filename && l.filename && streq(filename, l.filename)) )
		return first_line == l.first_line && last_line == l.last_line;
	else
		return false;
	}

int BroObj::suppress_runtime = 0;

BroObj::~BroObj()
	{
	delete location;
	}

void BroObj::Warn(const char* msg, const BroObj* obj2, int pinpoint_only) const
	{
	DoMsg("warning,", msg, obj2, pinpoint_only);
	++nwarn;
	}

void BroObj::Error(const char* msg, const BroObj* obj2, int pinpoint_only) const
	{
	DoMsg("error,", msg, obj2, pinpoint_only);
	++nerr;
	}

void BroObj::RunTime(const char* msg, const BroObj* obj2, int pinpoint_only) const
	{
	if ( ! suppress_runtime )
		{
		DoMsg("run-time error,", msg, obj2, pinpoint_only);
		++nruntime;
		}
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

	DoMsg("bad tag in", out);
	Fatal();
	}

void BroObj::Internal(const char* msg) const
	{
	DoMsg("internal error:", msg);
	Fatal();
	}

void BroObj::InternalWarning(const char* msg) const
	{
	DoMsg("internal warning:", msg);
	}

void BroObj::AddLocation(ODesc* d) const
	{
	if ( ! location )
		{
		d->Add("<no location>");
		return;
		}

	if ( location->filename )
		{
		d->Add(location->filename);

		if ( location->first_line == 0 )
			return;

		d->AddSP(",");
		}

	if ( location->last_line != location->first_line )
		{
		d->Add("lines ");
		d->Add(location->first_line);
		d->Add("-");
		d->Add(location->last_line);
		}
	else
		{
		d->Add("line ");
		d->Add(location->first_line);
		}
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

void BroObj::DoMsg(const char s1[], const char s2[], const BroObj* obj2,
			int pinpoint_only) const
	{
	ODesc d;
	d.SetShort();

	PinPoint(&d, obj2, pinpoint_only);
	d.SP();
	d.Add(s1);
	d.SP();
	d.Add(s2);
	fprintf(stderr, "%s\n", d.Description());
	}

void BroObj::PinPoint(ODesc* d, const BroObj* obj2, int pinpoint_only) const
	{
	if ( network_time > 0.0 )
		{
		char time[256];
		safe_snprintf(time, sizeof(time), "%.6f", network_time);
		d->Add(time);
		d->SP();
		}

	AddLocation(d);
	if ( obj2 && obj2->GetLocationInfo() != &no_location &&
	     *obj2->GetLocationInfo() != *GetLocationInfo() )
		{
		d->Add(" and ");
		obj2->AddLocation(d);
		d->Add("\n  ");
		}

	d->Add(" (");
	Describe(d);
	if ( obj2 && ! pinpoint_only )
		{
		d->Add(" and ");
		obj2->Describe(d);
		}

	d->Add("):");
	}

void BroObj::Fatal() const
	{
#ifdef DEBUG_BRO
	internal_error("BroObj::Fatal()");
#endif
	exit(1);
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
	internal_error("bad reference count [%d]", type);
	abort();
	}

void bro_obj_delete_func(void* v)
	{
	Unref((BroObj*) v);
	}
