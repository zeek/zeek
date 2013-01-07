//
// Runtime functions supporting the generated HILTI/BinPAC++ code.
//
// These function all assume "HILTI-C" linkage.

#include "Runtime.h"

#undef DBG_LOG
#include "Conn.h"
#include "Val.h"
#include "Event.h"
#include "Pac2Analyzer.h"
#undef List

#include <hilti/context.h>

namespace bro {
namespace hilti {

// When adding new runtime functions, you must extend this function table in
// RuntimeFunctionTable.cc, or the JIT compiler will not be able to find
// them.
extern const ::hilti::CompilerContext::FunctionMapping libbro_function_table[] = {
	{ "libbro_cookie_to_conn_val", (void*)&libbro_cookie_to_conn_val },
	{ "libbro_cookie_to_is_orig", (void*)&libbro_cookie_to_is_orig },
	{ "libbro_h2b_bytes", (void*)&libbro_h2b_bytes},
	{ "libbro_raise_event", (void*)&libbro_raise_event },
	{ 0, 0 } // End marker.
};

}
}

extern "C"  {

void* libbro_cookie_to_conn_val(void* cookie, hlt_exception** excpt, hlt_execution_context* ctx)
	{
	auto c = (bro::hilti::Pac2_Analyzer::Cookie*)cookie;
	return c->analyzer->Conn()->BuildConnVal();
	}

void* libbro_cookie_to_is_orig(void* cookie, hlt_exception** excpt, hlt_execution_context* ctx)
	{
	auto c = (bro::hilti::Pac2_Analyzer::Cookie*)cookie;
	return new Val(c->is_orig, TYPE_BOOL);
	}

void* libbro_h2b_bytes(hlt_bytes* value, hlt_exception** excpt, hlt_execution_context* ctx)
	{
	int len = hlt_bytes_len(value, excpt, ctx);
	char* data = (char *)hlt_bytes_to_raw(value, excpt, ctx);
	Val* v = new StringVal(len, data);
	hlt_free(data);
	return v;
	}

void libbro_raise_event(hlt_bytes* name, const hlt_type_info* type, const void* tuple, hlt_exception** excpt, hlt_execution_context* ctx)
	{
	hlt_bytes_size len = hlt_bytes_len(name, excpt, ctx);
	char evname[len + 1];
	hlt_bytes_to_raw_buffer(name, (int8_t*)evname, len, excpt, ctx);
	evname[len] = '\0';

	EventHandlerPtr ev = event_registry->Lookup(evname);

	if ( ! ev.Ptr() )
		reporter->InternalError("unknown event '%s' triggered by HILTI code", evname);

	int16_t* offsets = (int16_t *)type->aux;

	val_list* vals = new val_list;

	for ( int i = 0; i < type->num_params; i++ )
		{
		Val* broval = *((Val**)(((char*)tuple) + offsets[i]));
		vals->append(broval);
		}

#ifdef DEBUG
	ODesc d;
	describe_vals(vals, &d);
	DBG_LOG(DBG_PAC2, "Queuing event '%s(%s)'", evname, d.Description());
#endif

	mgr.QueueEvent(ev, vals);
	}

}


