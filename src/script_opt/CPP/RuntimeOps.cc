// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/ZeekString.h"
#include "zeek/RunState.h"
#include "zeek/EventRegistry.h"
#include "zeek/IPAddr.h"
#include "zeek/script_opt/CPP/RuntimeOps.h"

namespace zeek::detail {

StringValPtr str_concat__CPP(const String* s1, const String* s2)
	{
	std::vector<const String*> strings(2);
	strings[0] = s1;
	strings[1] = s2;

	return make_intrusive<StringVal>(concatenate(strings));
	}

bool str_in__CPP(const String* s1, const String* s2)
	{
	auto s = reinterpret_cast<const unsigned char*>(s1->CheckString());
	return util::strstr_n(s2->Len(), s2->Bytes(), s1->Len(), s) != -1;
	}

ListValPtr index_val__CPP(std::vector<ValPtr> indices)
	{
	auto ind_v = make_intrusive<ListVal>(TYPE_ANY);

	// In the future, we could provide N versions of this that
	// unroll the loop.
	for ( auto i : indices )
		ind_v->Append(i);

	return ind_v;
	}

ValPtr index_table__CPP(const TableValPtr& t, std::vector<ValPtr> indices)
	{
	auto v = t->FindOrDefault(index_val__CPP(std::move(indices)));
	if ( ! v )
		reporter->CPPRuntimeError("no such index");
	return v;
	}

ValPtr index_vec__CPP(const VectorValPtr& vec, int index)
	{
	auto v = vec->ValAt(index);
	if ( ! v )
		reporter->CPPRuntimeError("no such index");
	return v;
	}

ValPtr index_string__CPP(const StringValPtr& svp, std::vector<ValPtr> indices)
	{
	return index_string(svp->AsString(),
				index_val__CPP(std::move(indices)).get());
	}

ValPtr set_event__CPP(IDPtr g, ValPtr v, EventHandlerPtr& gh)
	{
	g->SetVal(std::move(v));
	gh = event_registry->Register(g->Name());
	return v;
	}

ValPtr cast_value_to_type__CPP(const ValPtr& v, const TypePtr& t)
	{
	auto result = cast_value_to_type(v.get(), t.get());
	if ( ! result )
		reporter->CPPRuntimeError("invalid cast of value with type '%s' to type '%s'",
			type_name(v->GetType()->Tag()), type_name(t->Tag()));
	return result;
	}

SubNetValPtr addr_mask__CPP(const IPAddr& a, uint32_t mask)
	{
        if ( a.GetFamily() == IPv4 )
                {
                if ( mask > 32 )
                        reporter->CPPRuntimeError("bad IPv4 subnet prefix length: %d", int(mask));
                }
        else
                {
                if ( mask > 128 )
                        reporter->CPPRuntimeError("bad IPv6 subnet prefix length: %d", int(mask));
                }

        return make_intrusive<SubNetVal>(a, mask);
	}


// Helper function for reporting invalidation of interators.
static void check_iterators__CPP(bool invalid)
	{
	if ( invalid )
		reporter->Warning("possible loop/iterator invalidation in compiled code");
	}

// Template for aggregate assignments of the form "v1[v2] = v3".
template <typename T>
ValPtr assign_to_index__CPP(T v1, ValPtr v2, ValPtr v3)
	{
	bool iterators_invalidated = false;
	auto err_msg = assign_to_index(std::move(v1), std::move(v2), v3, iterators_invalidated);

	check_iterators__CPP(iterators_invalidated);

	if ( err_msg )
		reporter->CPPRuntimeError("%s", err_msg);

	return v3;
	}

ValPtr assign_to_index__CPP(TableValPtr v1, ValPtr v2, ValPtr v3)
	{
	return assign_to_index__CPP<TableValPtr>(v1, v2, v3);
	}
ValPtr assign_to_index__CPP(VectorValPtr v1, ValPtr v2, ValPtr v3)
	{
	return assign_to_index__CPP<VectorValPtr>(v1, v2, v3);
	}
ValPtr assign_to_index__CPP(StringValPtr v1, ValPtr v2, ValPtr v3)
	{
	return assign_to_index__CPP<StringValPtr>(v1, v2, v3);
	}

void add_element__CPP(TableValPtr aggr, ListValPtr indices)
	{
	bool iterators_invalidated = false;
	aggr->Assign(indices, nullptr, true, &iterators_invalidated);
	check_iterators__CPP(iterators_invalidated);
	}

void remove_element__CPP(TableValPtr aggr, ListValPtr indices)
	{
	bool iterators_invalidated = false;
	aggr->Remove(*indices.get(), true, &iterators_invalidated);
	check_iterators__CPP(iterators_invalidated);
	}

// A helper function that takes a parallel vectors of attribute tags
// and values and returns a collective AttributesPtr corresponding to
// those instantiated attributes.  For attributes that don't have
// associated expressions, the correspoinding value should be nil.
static AttributesPtr build_attrs__CPP(std::vector<int> attr_tags,
				      std::vector<ValPtr> attr_vals)
	{
	std::vector<AttrPtr> attrs;
	int nattrs = attr_tags.size();
	for ( auto i = 0; i < nattrs; ++i )
		{
		auto t_i = AttrTag(attr_tags[i]);
		const auto& v_i = attr_vals[i];
		ExprPtr e;

		if ( v_i )
			e = make_intrusive<ConstExpr>(v_i);

		attrs.emplace_back(make_intrusive<Attr>(t_i, e));
		}

	return make_intrusive<Attributes>(std::move(attrs), nullptr, false, false);
	}

TableValPtr set_constructor__CPP(std::vector<ValPtr> elements, TableTypePtr t,
                                 std::vector<int> attr_tags,
                                 std::vector<ValPtr> attr_vals)
	{
	auto attrs = build_attrs__CPP(std::move(attr_tags), std::move(attr_vals));
	auto aggr = make_intrusive<TableVal>(std::move(t), std::move(attrs));

	for ( const auto& elem : elements )
		aggr->Assign(std::move(elem), nullptr);

	return aggr;
	}

TableValPtr table_constructor__CPP(std::vector<ValPtr> indices,
                                   std::vector<ValPtr> vals, TableTypePtr t,
                                   std::vector<int> attr_tags,
                                   std::vector<ValPtr> attr_vals)
	{
	const auto& yt = t->Yield().get();
	auto n = indices.size();

	auto attrs = build_attrs__CPP(std::move(attr_tags), std::move(attr_vals));
	auto aggr = make_intrusive<TableVal>(std::move(t), std::move(attrs));

	for ( auto i = 0; i < n; ++i )
		{
		auto v = check_and_promote(vals[i], yt, true);
		if ( v )
			aggr->Assign(std::move(indices[i]), std::move(v));
		}

	return aggr;
	}

RecordValPtr record_constructor__CPP(std::vector<ValPtr> vals, RecordTypePtr t)
	{
	auto rv = make_intrusive<RecordVal>(std::move(t));
	auto n = vals.size();

	rv->Reserve(n);

	for ( auto i = 0; i < n; ++i )
		rv->Assign(i, vals[i]);

	return rv;
	}

VectorValPtr vector_constructor__CPP(std::vector<ValPtr> vals, VectorTypePtr t)
	{
	auto vv = make_intrusive<VectorVal>(std::move(t));
	auto n = vals.size();

	for ( auto i = 0; i < n; ++i )
		vv->Assign(i, vals[i]);

	return vv;
	}

ValPtr schedule__CPP(double dt, EventHandlerPtr event, std::vector<ValPtr> args)
	{
	if ( ! run_state::terminating )
		timer_mgr->Add(new ScheduleTimer(event, std::move(args), dt));

	return nullptr;
	}

} // namespace zeek::detail
