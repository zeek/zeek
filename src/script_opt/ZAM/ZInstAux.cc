// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/script_opt/ZAM/ZInstAux.h"

#include "zeek/module_util.h"

namespace zeek::detail {

void ZInstAux::Dump(FILE* f) const {
    if ( id_val )
        fprintf(f, " id=%s", id_val->Name());

    if ( call_expr )
        fprintf(f, " <callexpr>");

    if ( func )
        fprintf(f, " func=%s", func->GetName().c_str());

    if ( is_BiF_call )
        fprintf(f, " <BiF>");

    if ( lambda )
        fprintf(f, " <lambda>");

    if ( event_handler )
        fprintf(f, " eh=%s", event_handler->Name());

    if ( attrs )
        fprintf(f, " <attrs>");

    if ( ! types.empty() )
        fprintf(f, " types=%zu", types.size());

    if ( ! is_managed.empty() )
        fprintf(f, " is_managed=%zu", is_managed.size());

    if ( ! map.empty() )
        fprintf(f, " map=%zu", map.size());

    if ( ! rhs_map.empty() )
        fprintf(f, " rhs_map=%zu", rhs_map.size());

    if ( ! lhs_map.empty() )
        fprintf(f, " lhs_map=%zu", lhs_map.size());

    for ( auto lv : loop_vars )
        fprintf(f, " loop_var=%d", lv);

    if ( value_var_type )
        fprintf(f, " <value-var-type>");

    if ( field_inits )
        fprintf(f, " field_inits=%zu", field_inits->size());

    if ( elems ) {
        for ( int i = 0; i < n; ++i ) {
            auto& e_i = elems[i];
            auto& c = e_i.Constant();

            fprintf(f, " elem-%d:", i);

            ASSERT(elems_has_slots == (e_i.GetType() != nullptr));
            if ( c )
                fprintf(f, "<constant>");

            else if ( e_i.GetType() )
                fprintf(f, "<slot:%d>", e_i.Slot());

            else
                fprintf(f, "<int:%d>", e_i.Slot());
        }
    }

    if ( ! cft.empty() ) {
        fprintf(f, " CFT: ");
        bool first = true;
        for ( auto [cft, n] : cft ) {
            const char* cn;
            switch ( cft ) {
                case CFT_IF: cn = "if"; break;
                case CFT_BLOCK_END: cn = "block-end"; break;
                case CFT_ELSE: cn = "else"; break;
                case CFT_LOOP: cn = "loop"; break;
                case CFT_LOOP_COND: cn = "loop-cond"; break;
                case CFT_LOOP_END: cn = "loop-end"; break;
                case CFT_NEXT: cn = "next"; break;
                case CFT_BREAK: cn = "break"; break;
                case CFT_DEFAULT: cn = "default"; break;
                case CFT_INLINED_RETURN: cn = "inline-return"; break;
                default: cn = "unknown"; break;
            }

            if ( first )
                first = false;
            else
                fprintf(f, "/");

            fprintf(f, "%s", cn);
        }
    }
}

TraversalCode ZInstAux::Traverse(TraversalCallback* cb) const {
    TraversalCode tc;

    if ( id_val ) {
        tc = id_val->Traverse(cb);
        HANDLE_TC_STMT_PRE(tc);
    }

    // Don't traverse the "func" field, as if it's a recursive function
    // we can wind up right back here.

    if ( lambda ) {
        tc = lambda->Traverse(cb);
        HANDLE_TC_STMT_PRE(tc);
    }

    if ( event_handler ) {
        auto g = lookup_ID(event_handler->Name(), GLOBAL_MODULE_NAME, false, false, false);
        ASSERT(g);
        tc = g->Traverse(cb);
        HANDLE_TC_STMT_PRE(tc);
    }

    if ( attrs ) {
        tc = attrs->Traverse(cb);
        HANDLE_TC_STMT_PRE(tc);
    }

    if ( value_var_type ) {
        tc = value_var_type->Traverse(cb);
        HANDLE_TC_STMT_PRE(tc);
    }

    for ( auto& lvt : types ) {
        tc = lvt->Traverse(cb);
        HANDLE_TC_STMT_PRE(tc);
    }

    if ( elems ) {
        for ( int i = 0; i < n; ++i ) {
            auto& e_i = elems[i];

            auto& c = e_i.Constant();
            if ( c ) {
                tc = c->GetType()->Traverse(cb);
                HANDLE_TC_STMT_PRE(tc);
            }

            auto& t = e_i.GetType();
            if ( t ) {
                tc = t->Traverse(cb);
                HANDLE_TC_STMT_PRE(tc);
            }
        }
    }

    return TC_CONTINUE;
}

} // namespace zeek::detail
