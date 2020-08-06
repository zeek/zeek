// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"
#include "Obj.h"

#include <stdlib.h>

#include "Desc.h"
#include "Func.h"
#include "File.h"
#include "plugin/Manager.h"

namespace zeek {
namespace detail {

Location start_location("<start uninitialized>", 0, 0, 0, 0);
Location end_location("<end uninitialized>", 0, 0, 0, 0);

void Location::Describe(zeek::ODesc* d) const
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
	     (filename && l.filename && zeek::util::streq(filename, l.filename)) )
		return first_line == l.first_line && last_line == l.last_line;
	else
		return false;
	}

} // namespace detail

int Obj::suppress_errors = 0;

Obj::~Obj()
	{
	if ( notify_plugins )
		PLUGIN_HOOK_VOID(HOOK_BRO_OBJ_DTOR, HookBroObjDtor(this));

	delete location;
	}

void Obj::Warn(const char* msg, const Obj* obj2, bool pinpoint_only, const detail::Location* expr_location) const
	{
	zeek::ODesc d;
	DoMsg(&d, msg, obj2, pinpoint_only, expr_location);
	zeek::reporter->Warning("%s", d.Description());
	zeek::reporter->PopLocation();
	}

void Obj::Error(const char* msg, const Obj* obj2, bool pinpoint_only, const detail::Location* expr_location) const
	{
	if ( suppress_errors )
		return;

	zeek::ODesc d;
	DoMsg(&d, msg, obj2, pinpoint_only, expr_location);
	zeek::reporter->Error("%s", d.Description());
	zeek::reporter->PopLocation();
	}

void Obj::BadTag(const char* msg, const char* t1, const char* t2) const
	{
	char out[512];

	if ( t2 )
		snprintf(out, sizeof(out), "%s (%s/%s)", msg, t1, t2);
	else if ( t1 )
		snprintf(out, sizeof(out), "%s (%s)", msg, t1);
	else
		snprintf(out, sizeof(out), "%s", msg);

	zeek::ODesc d;
	DoMsg(&d, out);
	zeek::reporter->FatalErrorWithCore("%s", d.Description());
	zeek::reporter->PopLocation();
	}

void Obj::Internal(const char* msg) const
	{
	zeek::ODesc d;
	DoMsg(&d, msg);
	auto rcs = zeek::render_call_stack();

	if ( rcs.empty() )
		zeek::reporter->InternalError("%s", d.Description());
	else
		zeek::reporter->InternalError("%s, call stack: %s", d.Description(), rcs.data());

	zeek::reporter->PopLocation();
	}

void Obj::InternalWarning(const char* msg) const
	{
	zeek::ODesc d;
	DoMsg(&d, msg);
	zeek::reporter->InternalWarning("%s", d.Description());
	zeek::reporter->PopLocation();
	}

void Obj::AddLocation(zeek::ODesc* d) const
	{
	if ( ! location )
		{
		d->Add("<no location>");
		return;
		}

	location->Describe(d);
	}

bool Obj::SetLocationInfo(const detail::Location* start, const detail::Location* end)
	{
	if ( ! start || ! end )
		return false;

	if ( end->filename && ! zeek::util::streq(start->filename, end->filename) )
		return false;

	if ( location && (start == &zeek::detail::no_location || end == &zeek::detail::no_location) )
		// We already have a better location, so don't use this one.
		return true;

	delete location;

	location = new detail::Location(start->filename,
	                                start->first_line, end->last_line,
	                                start->first_column, end->last_column);

	return true;
	}

void Obj::UpdateLocationEndInfo(const detail::Location& end)
	{
	if ( ! location )
		SetLocationInfo(&end, &end);

	location->last_line = end.last_line;
	location->last_column = end.last_column;
	}

void Obj::DoMsg(zeek::ODesc* d, const char s1[], const Obj* obj2,
                bool pinpoint_only, const detail::Location* expr_location) const
	{
	d->SetShort();

	d->Add(s1);
	PinPoint(d, obj2, pinpoint_only);

	const detail::Location* loc2 = nullptr;
	if ( obj2 && obj2->GetLocationInfo() != &zeek::detail::no_location &&
		 *obj2->GetLocationInfo() != *GetLocationInfo() )
		loc2 = obj2->GetLocationInfo();
	else if ( expr_location )
		loc2 = expr_location;

	zeek::reporter->PushLocation(GetLocationInfo(), loc2);
	}

void Obj::PinPoint(zeek::ODesc* d, const Obj* obj2, bool pinpoint_only) const
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

void Obj::Print() const
	{
	static zeek::File fstderr(stderr);
	zeek::ODesc d(DESC_READABLE, &fstderr);
	Describe(&d);
	d.Add("\n");
	}

void bad_ref(int type)
	{
	zeek::reporter->InternalError("bad reference count [%d]", type);
	abort();
	}

void obj_delete_func(void* v)
	{
	Unref((Obj*) v);
	}

} // namespace zeek

void print(const zeek::Obj* obj)
	{
	obj->Print();
	}
