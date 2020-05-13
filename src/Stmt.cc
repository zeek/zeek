// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"

#include "CompHash.h"
#include "Expr.h"
#include "Event.h"
#include "Frame.h"
#include "File.h"
#include "Reporter.h"
#include "NetVar.h"
#include "Stmt.h"
#include "Scope.h"
#include "Var.h"
#include "Desc.h"
#include "Debug.h"
#include "Traverse.h"
#include "Trigger.h"
#include "IntrusivePtr.h"
#include "logging/Manager.h"
#include "logging/logging.bif.h"

const char* stmt_name(BroStmtTag t)
	{
	static const char* stmt_names[int(NUM_STMTS)] = {
		"alarm", // Does no longer exist, but kept for keeping enums consistent.
		"print", "event", "expr", "if", "when", "switch",
		"for", "next", "break", "return", "add", "delete",
		"list", "bodylist",
		"<init>", "fallthrough", "while",
		"null",
	};

	return stmt_names[int(t)];
	}

Stmt::Stmt(BroStmtTag arg_tag)
	{
	tag = arg_tag;
	breakpoint_count = 0;
	last_access = 0;
	access_count = 0;

	SetLocationInfo(&start_location, &end_location);
	}

Stmt::~Stmt()
	{
	}

bool Stmt::SetLocationInfo(const Location* start, const Location* end)
	{
	if ( ! BroObj::SetLocationInfo(start, end) )
		return false;

	// Update the Filemap of line number -> statement mapping for
	// breakpoints (Debug.h).
	auto map_iter = g_dbgfilemaps.find(location->filename);
	if ( map_iter == g_dbgfilemaps.end() )
		return false;

	Filemap& map = *(map_iter->second);

	StmtLocMapping* new_mapping = new StmtLocMapping(GetLocationInfo(), this);

	// Optimistically just put it at the end.
	map.push_back(new_mapping);

	int curr_idx = map.length() - 1;
	if ( curr_idx == 0 )
		return true;

	// In case it wasn't actually lexically last, bubble it to the
	// right place.
	while ( map[curr_idx - 1]->StartsAfter(map[curr_idx]) )
		{
		StmtLocMapping t = *map[curr_idx - 1];
		*map[curr_idx - 1] = *map[curr_idx];
		*map[curr_idx] = t;
		curr_idx--;
		}

	return true;
	}

bool Stmt::IsPure() const
	{
	return false;
	}

void Stmt::Describe(ODesc* d) const
	{
	if ( ! d->IsReadable() || Tag() != STMT_EXPR )
		AddTag(d);
	}

void Stmt::DecrBPCount()
	{
	if ( breakpoint_count )
		--breakpoint_count;
	else
		reporter->InternalError("breakpoint count decremented below 0");
	}

void Stmt::AddTag(ODesc* d) const
	{
	if ( d->IsBinary() )
		d->Add(int(Tag()));
	else
		d->Add(stmt_name(Tag()));
	d->SP();
	}

void Stmt::DescribeDone(ODesc* d) const
	{
	if ( d->IsReadable() && ! d->IsShort() )
		d->Add(";");
	}

void Stmt::AccessStats(ODesc* d) const
	{
	if ( d->IncludeStats() )
		{
		d->Add("(@");
		d->Add(last_access ? fmt_access_time(last_access) : "<never>");
		d->Add(" #");
		d->Add(access_count);
		d->Add(")");
		d->NL();
		}
	}

ExprListStmt::ExprListStmt(BroStmtTag t, IntrusivePtr<ListExpr> arg_l)
	: Stmt(t), l(std::move(arg_l))
	{
	const expr_list& e = l->Exprs();
	for ( const auto& expr : e )
		{
		const auto& t = expr->GetType();
		if ( ! t || t->Tag() == TYPE_VOID )
			Error("value of type void illegal");
		}

	SetLocationInfo(l->GetLocationInfo());
	}

ExprListStmt::~ExprListStmt() = default;

IntrusivePtr<Val> ExprListStmt::Exec(Frame* f, stmt_flow_type& flow) const
	{
	last_access = network_time;
	flow = FLOW_NEXT;

	auto vals = eval_list(f, l.get());

	if ( vals )
		return DoExec(std::move(*vals), flow);

	return nullptr;
	}

void ExprListStmt::Describe(ODesc* d) const
	{
	Stmt::Describe(d);
	l->Describe(d);
	DescribeDone(d);
	}

TraversalCode ExprListStmt::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreStmt(this);
	HANDLE_TC_STMT_PRE(tc);

	const expr_list& e = l->Exprs();
	for ( const auto& expr : e )
		{
		tc = expr->Traverse(cb);
		HANDLE_TC_STMT_PRE(tc);
		}

	tc = cb->PostStmt(this);
	HANDLE_TC_STMT_POST(tc);
	}

static BroFile* print_stdout = nullptr;

static IntrusivePtr<EnumVal> lookup_enum_val(const char* module_name, const char* name)
	{
	const auto& id = lookup_ID(name, module_name);
	assert(id);
	assert(id->IsEnumConst());

	EnumType* et = id->GetType()->AsEnumType();

	int index = et->Lookup(module_name, name);
	assert(index >= 0);

	return et->GetVal(index);
	}

static void print_log(const std::vector<IntrusivePtr<Val>>& vals)
	{
	auto plval = lookup_enum_val("Log", "PRINTLOG");
	auto record = make_intrusive<RecordVal>(zeek::id::lookup_type("Log::PrintLogInfo")->AsRecordType());
	auto vec = make_intrusive<VectorVal>(zeek::id::string_vec);

	for ( const auto& val : vals )
		{
		ODesc d(DESC_READABLE);
		val->Describe(&d);
		vec->Assign(vec->Size(), make_intrusive<StringVal>(d.Description()));
		}

	record->Assign(0, make_intrusive<Val>(current_time(), TYPE_TIME));
	record->Assign(1, std::move(vec));
	log_mgr->Write(plval.get(), record.get());
	}

IntrusivePtr<Val> PrintStmt::DoExec(std::vector<IntrusivePtr<Val>> vals,
                                    stmt_flow_type& /* flow */) const
	{
	RegisterAccess();

	if ( ! print_stdout )
		print_stdout = new BroFile(stdout);

	BroFile* f = print_stdout;
	int offset = 0;

	if ( vals.size() > 0 && (vals)[0]->GetType()->Tag() == TYPE_FILE )
		{
		f = (vals)[0]->AsFile();
		if ( ! f->IsOpen() )
			return nullptr;

		++offset;
		}

	static auto print_log_type = static_cast<BifEnum::Log::PrintLogType>(
	        zeek::id::lookup_val("Log::print_to_log")->AsEnum());

	switch ( print_log_type ) {
	case BifEnum::Log::REDIRECT_NONE:
		break;
	case BifEnum::Log::REDIRECT_ALL:
		{
		print_log(vals);
		return nullptr;
		}
	case BifEnum::Log::REDIRECT_STDOUT:
		if ( f->File() == stdout )
			{
			// Should catch even printing to a "manually opened" stdout file,
			// like "/dev/stdout" or "-".
			print_log(vals);
			return nullptr;
			}
		break;
	default:
		reporter->InternalError("unknown Log::PrintLogType value: %d",
		                        print_log_type);
		break;
	}

	desc_style style = f->IsRawOutput() ? RAW_STYLE : STANDARD_STYLE;

	if ( f->IsRawOutput() )
		{
		ODesc d(DESC_READABLE);
		d.SetFlush(false);
		d.SetStyle(style);

		describe_vals(vals, &d, offset);
		f->Write(d.Description(), d.Len());
		}
	else
		{
		ODesc d(DESC_READABLE, f);
		d.SetFlush(false);
		d.SetStyle(style);

		describe_vals(vals, &d, offset);
		f->Write("\n", 1);
		}

	return nullptr;
	}

ExprStmt::ExprStmt(IntrusivePtr<Expr> arg_e) : Stmt(STMT_EXPR), e(std::move(arg_e))
	{
	if ( e && e->IsPure() )
		Warn("expression value ignored");

	SetLocationInfo(e->GetLocationInfo());
	}

ExprStmt::ExprStmt(BroStmtTag t, IntrusivePtr<Expr> arg_e) : Stmt(t), e(std::move(arg_e))
	{
	if ( e )
		SetLocationInfo(e->GetLocationInfo());
	}

ExprStmt::~ExprStmt() = default;

IntrusivePtr<Val> ExprStmt::Exec(Frame* f, stmt_flow_type& flow) const
	{
	RegisterAccess();
	flow = FLOW_NEXT;

	auto v = e->Eval(f);

	if ( v )
		return DoExec(f, v.get(), flow);
	else
		return nullptr;
	}

IntrusivePtr<Val> ExprStmt::DoExec(Frame* /* f */, Val* /* v */, stmt_flow_type& /* flow */) const
	{
	return nullptr;
	}

bool ExprStmt::IsPure() const
	{
	return ! e || e->IsPure();
	}

void ExprStmt::Describe(ODesc* d) const
	{
	Stmt::Describe(d);

	if ( d->IsReadable() && Tag() == STMT_IF )
		d->Add("(");
	e->Describe(d);

	if ( Tag() == STMT_IF || Tag() == STMT_SWITCH )
		{
		if ( d->IsReadable() )
			{
			if ( Tag() == STMT_IF )
				d->Add(")");
			d->SP();
			}
		}
	else
		DescribeDone(d);
	}

TraversalCode ExprStmt::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreStmt(this);
	HANDLE_TC_STMT_PRE(tc);

	if ( e )
		{
		tc = e->Traverse(cb);
		HANDLE_TC_STMT_PRE(tc);
		}

	tc = cb->PostStmt(this);
	HANDLE_TC_STMT_POST(tc);
	}

IfStmt::IfStmt(IntrusivePtr<Expr> test,
               IntrusivePtr<Stmt> arg_s1, IntrusivePtr<Stmt> arg_s2)
	: ExprStmt(STMT_IF, std::move(test)),
	  s1(std::move(arg_s1)), s2(std::move(arg_s2))
	{
	if ( ! e->IsError() && ! IsBool(e->GetType()->Tag()) )
		e->Error("conditional in test must be boolean");

	const Location* loc1 = s1->GetLocationInfo();
	const Location* loc2 = s2->GetLocationInfo();
	SetLocationInfo(loc1, loc2);
	}

IfStmt::~IfStmt() = default;

IntrusivePtr<Val> IfStmt::DoExec(Frame* f, Val* v, stmt_flow_type& flow) const
	{
	// Treat 0 as false, but don't require 1 for true.
	Stmt* do_stmt = v->IsZero() ? s2.get() : s1.get();

	f->SetNextStmt(do_stmt);

	if ( ! pre_execute_stmt(do_stmt, f) )
		{ // ### Abort or something
		}

	auto result = do_stmt->Exec(f, flow);

	if ( ! post_execute_stmt(do_stmt, f, result.get(), &flow) )
		{ // ### Abort or something
		}

	return result;
	}

bool IfStmt::IsPure() const
	{
	return e->IsPure() && s1->IsPure() && s2->IsPure();
	}

void IfStmt::Describe(ODesc* d) const
	{
	ExprStmt::Describe(d);

	d->PushIndent();
	s1->AccessStats(d);
	s1->Describe(d);
	d->PopIndent();

	if ( d->IsReadable() )
		{
		if ( s2->Tag() != STMT_NULL )
			{
			d->Add("else");
			d->PushIndent();
			s2->AccessStats(d);
			s2->Describe(d);
			d->PopIndent();
			}
		}
	else
		s2->Describe(d);
	}

TraversalCode IfStmt::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreStmt(this);
	HANDLE_TC_STMT_PRE(tc);

	// Condition is stored in base class's "e" field.
	tc = e->Traverse(cb);
	HANDLE_TC_STMT_PRE(tc);

	tc = TrueBranch()->Traverse(cb);
	HANDLE_TC_STMT_PRE(tc);

	tc = FalseBranch()->Traverse(cb);
	HANDLE_TC_STMT_PRE(tc);

	tc = cb->PostStmt(this);
	HANDLE_TC_STMT_POST(tc);
	}

static BroStmtTag get_last_stmt_tag(const Stmt* stmt)
	{
	if ( ! stmt )
		return STMT_NULL;

	if ( stmt->Tag() != STMT_LIST )
		return stmt->Tag();

	const StmtList* stmts = stmt->AsStmtList();
	int len = stmts->Stmts().length();

	if ( len == 0 )
		return STMT_LIST;

	return get_last_stmt_tag(stmts->Stmts()[len - 1]);
	}

Case::Case(IntrusivePtr<ListExpr> arg_expr_cases, id_list* arg_type_cases,
           IntrusivePtr<Stmt> arg_s)
	: expr_cases(std::move(arg_expr_cases)), type_cases(arg_type_cases),
	  s(std::move(arg_s))
	{
	BroStmtTag t = get_last_stmt_tag(Body());

	if ( t != STMT_BREAK && t != STMT_FALLTHROUGH && t != STMT_RETURN )
		Error("case block must end in break/fallthrough/return statement");
	}

Case::~Case()
	{
	for ( const auto& id : *type_cases )
		Unref(id);

	delete type_cases;
	}

void Case::Describe(ODesc* d) const
	{
	if ( ! (expr_cases || type_cases) )
		{
		if ( ! d->IsBinary() )
			d->Add("default:");

		d->AddCount(0);

		d->PushIndent();
		Body()->AccessStats(d);
		Body()->Describe(d);
		d->PopIndent();

		return;
		}

	if ( ! d->IsBinary() )
		d->Add("case");

	if ( expr_cases )
		{
		const expr_list& e = expr_cases->Exprs();

		d->AddCount(e.length());

		loop_over_list(e, i)
			{
			if ( i > 0 && d->IsReadable() )
				d->Add(",");

			d->SP();
			e[i]->Describe(d);
			}
		}

	if ( type_cases )
		{
		const id_list& t = *type_cases;

		d->AddCount(t.length());

		loop_over_list(t, i)
			{
			if ( i > 0 && d->IsReadable() )
				d->Add(",");

			d->SP();
			d->Add("type");
			d->SP();
			t[i]->GetType()->Describe(d);

			if ( t[i]->Name() )
				{
				d->SP();
				d->Add("as");
				d->SP();
				d->Add(t[i]->Name());
				}
			}
		}

	if ( d->IsReadable() )
		d->Add(":");

	d->PushIndent();
	Body()->AccessStats(d);
	Body()->Describe(d);
	d->PopIndent();
	}

TraversalCode Case::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc;

	if ( expr_cases )
		{
		tc = expr_cases->Traverse(cb);
		HANDLE_TC_STMT_PRE(tc);
		}

	if ( type_cases )
		{
		// No traverse support for types.
		}

	tc = s->Traverse(cb);
	HANDLE_TC_STMT_PRE(tc);

	return TC_CONTINUE;
	}

static void int_del_func(void* v)
	{
	delete (int*) v;
	}

void SwitchStmt::Init()
	{
	auto t = make_intrusive<TypeList>();
	t->Append(e->GetType());
	comp_hash = new CompositeHash(std::move(t));

	case_label_value_map.SetDeleteFunc(int_del_func);
	}

SwitchStmt::SwitchStmt(IntrusivePtr<Expr> index, case_list* arg_cases)
	: ExprStmt(STMT_SWITCH, std::move(index)),
	  cases(arg_cases), default_case_idx(-1)
	{
	Init();

	bool have_exprs = false;
	bool have_types = false;

	loop_over_list(*cases, i)
		{
		Case* c = (*cases)[i];
		ListExpr* le = c->ExprCases();
		id_list* tl = c->TypeCases();

		if ( le )
			{
			have_exprs = true;

			if ( ! is_atomic_type(e->GetType().get()) )
				e->Error("switch expression must be of an atomic type when cases are expressions");

			if ( ! le->GetType()->AsTypeList()->AllMatch(e->GetType().get(), false) )
				{
				le->Error("case expression type differs from switch type", e.get());
				continue;
				}

			expr_list& exprs = le->Exprs();

			loop_over_list(exprs, j)
				{
				if ( ! exprs[j]->IsConst() )
					{
					Expr* expr = exprs[j];

					switch ( expr->Tag() ) {
					// Simplify trivial unary plus/minus expressions on consts.
					case EXPR_NEGATE:
						{
						NegExpr* ne = (NegExpr*)(expr);

						if ( ne->Op()->IsConst() )
							Unref(exprs.replace(j, new ConstExpr(ne->Eval(nullptr))));
						}
						break;

					case EXPR_POSITIVE:
						{
						PosExpr* pe = (PosExpr*)(expr);

						if ( pe->Op()->IsConst() )
							Unref(exprs.replace(j, new ConstExpr(pe->Eval(nullptr))));
						}
						break;

					case EXPR_NAME:
						{
						NameExpr* ne = (NameExpr*)(expr);

						if ( ne->Id()->IsConst() )
							{
							auto v = ne->Eval(nullptr);

							if ( v )
								Unref(exprs.replace(j, new ConstExpr(std::move(v))));
							}
						}
						break;

					default:
						break;
					}
					}

				if ( ! exprs[j]->IsConst() )
					exprs[j]->Error("case label expression isn't constant");
				else
					{
					if ( ! AddCaseLabelValueMapping(exprs[j]->ExprVal(), i) )
						exprs[j]->Error("duplicate case label");
					}
				}
			}

		else if ( tl )
			{
			have_types = true;

			for ( const auto& t : *tl )
				{
				const auto& ct = t->GetType();

	   			if ( ! can_cast_value_to_type(e->GetType().get(), ct.get()) )
					{
					c->Error("cannot cast switch expression to case type");
					continue;
					}

				if ( ! AddCaseLabelTypeMapping(t, i) )
					{
					c->Error("duplicate case label");
					continue;
					}
				}
			}

		else
			{
			if ( default_case_idx != -1 )
				c->Error("multiple default labels", (*cases)[default_case_idx]);
			else
				default_case_idx = i;
			}
		}

	if ( have_exprs && have_types )
		Error("cannot mix cases with expressions and types");

	}

SwitchStmt::~SwitchStmt()
	{
	for ( const auto& c : *cases )
		Unref(c);

	delete cases;
	delete comp_hash;
	}

bool SwitchStmt::AddCaseLabelValueMapping(const Val* v, int idx)
	{
	HashKey* hk = comp_hash->ComputeHash(v, true);

	if ( ! hk )
		{
		reporter->PushLocation(e->GetLocationInfo());
		reporter->InternalError("switch expression type mismatch (%s/%s)",
		    type_name(v->GetType()->Tag()), type_name(e->GetType()->Tag()));
		}

	int* label_idx = case_label_value_map.Lookup(hk);

	if ( label_idx )
		{
		delete hk;
		return false;
		}

	case_label_value_map.Insert(hk, new int(idx));
	delete hk;
	return true;
	}

bool SwitchStmt::AddCaseLabelTypeMapping(ID* t, int idx)
	{
	for ( auto i : case_label_type_list )
		{
		if ( same_type(i.first->GetType().get(), t->GetType().get()) )
			return false;
		}

	auto e = std::make_pair(t, idx);
	case_label_type_list.push_back(e);

	return true;
	}

std::pair<int, ID*> SwitchStmt::FindCaseLabelMatch(const Val* v) const
	{
	int label_idx = -1;
	ID* label_id = nullptr;

	// Find matching expression cases.
	if ( case_label_value_map.Length() )
		{
		HashKey* hk = comp_hash->ComputeHash(v, true);

		if ( ! hk )
			{
			reporter->PushLocation(e->GetLocationInfo());
			reporter->Error("switch expression type mismatch (%s/%s)",
					type_name(v->GetType()->Tag()), type_name(e->GetType()->Tag()));
			return std::make_pair(-1, nullptr);
			}

		if ( auto i = case_label_value_map.Lookup(hk) )
			label_idx = *i;

		delete hk;
		}

	// Find matching type cases.
	for ( auto i : case_label_type_list )
		{
		auto id = i.first;
		const auto& type = id->GetType();

		if ( can_cast_value_to_type(v, type.get()) )
			{
			label_idx = i.second;
			label_id = id;
			break;
			}
		}

	if ( label_idx < 0 )
		return std::make_pair(default_case_idx, nullptr);
	else
		return std::make_pair(label_idx, label_id);
	}

IntrusivePtr<Val> SwitchStmt::DoExec(Frame* f, Val* v, stmt_flow_type& flow) const
	{
	IntrusivePtr<Val> rval;

	auto m = FindCaseLabelMatch(v);
	int matching_label_idx = m.first;
	ID* matching_id = m.second;

	if ( matching_label_idx == -1 )
		return nullptr;

	for ( int i = matching_label_idx; i < cases->length(); ++i )
		{
		const Case* c = (*cases)[i];

		if ( matching_id )
			{
			auto cv = cast_value_to_type(v, matching_id->GetType().get());
			f->SetElement(matching_id, cv.release());
			}

		flow = FLOW_NEXT;
		rval = c->Body()->Exec(f, flow);

		if ( flow == FLOW_BREAK  || flow == FLOW_RETURN )
			break;
		}

	if ( flow != FLOW_RETURN )
		flow = FLOW_NEXT;

	return rval;
	}

bool SwitchStmt::IsPure() const
	{
	if ( ! e->IsPure() )
		return false;

	for ( const auto& c : *cases )
		{
		if ( ! c->ExprCases()->IsPure() || ! c->Body()->IsPure() )
			return false;
		}

	return true;
	}

void SwitchStmt::Describe(ODesc* d) const
	{
	ExprStmt::Describe(d);

	if ( ! d->IsBinary() )
		d->Add("{");

	d->PushIndent();
	d->AddCount(cases->length());
	for ( const auto& c : *cases )
		c->Describe(d);
	d->PopIndent();

	if ( ! d->IsBinary() )
		d->Add("}");
	d->NL();
	}

TraversalCode SwitchStmt::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreStmt(this);
	HANDLE_TC_STMT_PRE(tc);

	// Index is stored in base class's "e" field.
	tc = e->Traverse(cb);
	HANDLE_TC_STMT_PRE(tc);

	for ( const auto& c : *cases )
		{
		tc = c->Traverse(cb);
		HANDLE_TC_STMT_PRE(tc);
		}

	tc = cb->PostStmt(this);
	HANDLE_TC_STMT_POST(tc);
	}

AddStmt::AddStmt(IntrusivePtr<Expr> arg_e) : ExprStmt(STMT_ADD, std::move(arg_e))
	{
	if ( ! e->CanAdd() )
		Error("illegal add statement");
	}

bool AddStmt::IsPure() const
	{
	return false;
	}

IntrusivePtr<Val> AddStmt::Exec(Frame* f, stmt_flow_type& flow) const
	{
	RegisterAccess();
	flow = FLOW_NEXT;
	e->Add(f);
	return nullptr;
	}


TraversalCode AddStmt::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreStmt(this);
	HANDLE_TC_STMT_PRE(tc);

	// Argument is stored in base class's "e" field.
	tc = e->Traverse(cb);
	HANDLE_TC_STMT_PRE(tc);

	tc = cb->PostStmt(this);
	HANDLE_TC_STMT_POST(tc);
	}

DelStmt::DelStmt(IntrusivePtr<Expr> arg_e) : ExprStmt(STMT_DELETE, std::move(arg_e))
	{
	if ( e->IsError() )
		return;

	if ( ! e->CanDel() )
		Error("illegal delete statement");
	}

bool DelStmt::IsPure() const
	{
	return false;
	}

IntrusivePtr<Val> DelStmt::Exec(Frame* f, stmt_flow_type& flow) const
	{
	RegisterAccess();
	flow = FLOW_NEXT;
	e->Delete(f);
	return nullptr;
	}

TraversalCode DelStmt::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreStmt(this);
	HANDLE_TC_STMT_PRE(tc);

	// Argument is stored in base class's "e" field.
	tc = e->Traverse(cb);
	HANDLE_TC_STMT_PRE(tc);

	tc = cb->PostStmt(this);
	HANDLE_TC_STMT_POST(tc);
	}

EventStmt::EventStmt(IntrusivePtr<EventExpr> arg_e)
	: ExprStmt(STMT_EVENT, arg_e), event_expr(std::move(arg_e))
	{
	}

IntrusivePtr<Val> EventStmt::Exec(Frame* f, stmt_flow_type& flow) const
	{
	RegisterAccess();
	auto args = eval_list(f, event_expr->Args());
	auto h = event_expr->Handler();

	if ( args && h )
		mgr.Enqueue(h, std::move(*args));

	flow = FLOW_NEXT;
	return nullptr;
	}

TraversalCode EventStmt::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreStmt(this);
	HANDLE_TC_STMT_PRE(tc);

	// Event is stored in base class's "e" field.
	tc = e->Traverse(cb);
	HANDLE_TC_STMT_PRE(tc);

	tc = cb->PostStmt(this);
	HANDLE_TC_STMT_POST(tc);
	}

WhileStmt::WhileStmt(IntrusivePtr<Expr> arg_loop_condition,
                     IntrusivePtr<Stmt> arg_body)
	: loop_condition(std::move(arg_loop_condition)), body(std::move(arg_body))
	{
	if ( ! loop_condition->IsError() &&
	     ! IsBool(loop_condition->GetType()->Tag()) )
		loop_condition->Error("while conditional must be boolean");
	}

WhileStmt::~WhileStmt() = default;

bool WhileStmt::IsPure() const
	{
	return loop_condition->IsPure() && body->IsPure();
	}

void WhileStmt::Describe(ODesc* d) const
	{
	Stmt::Describe(d);

	if ( d->IsReadable() )
		d->Add("(");

	loop_condition->Describe(d);

	if ( d->IsReadable() )
		d->Add(")");

	d->SP();
	d->PushIndent();
	body->AccessStats(d);
	body->Describe(d);
	d->PopIndent();
	}

TraversalCode WhileStmt::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreStmt(this);
	HANDLE_TC_STMT_PRE(tc);

	tc = loop_condition->Traverse(cb);
	HANDLE_TC_STMT_PRE(tc);

	tc = body->Traverse(cb);
	HANDLE_TC_STMT_PRE(tc);

	tc = cb->PostStmt(this);
	HANDLE_TC_STMT_POST(tc);
	}

IntrusivePtr<Val> WhileStmt::Exec(Frame* f, stmt_flow_type& flow) const
	{
	RegisterAccess();
	flow = FLOW_NEXT;
	IntrusivePtr<Val> rval;

	for ( ; ; )
		{
		auto cond = loop_condition->Eval(f);

		if ( ! cond )
			break;

		if ( ! cond->AsBool() )
			break;

		flow = FLOW_NEXT;
		rval = body->Exec(f, flow);

		if ( flow == FLOW_BREAK || flow == FLOW_RETURN )
			break;
		}

	if ( flow == FLOW_LOOP || flow == FLOW_BREAK )
		flow = FLOW_NEXT;

	return rval;
	}

ForStmt::ForStmt(id_list* arg_loop_vars, IntrusivePtr<Expr> loop_expr)
	: ExprStmt(STMT_FOR, std::move(loop_expr))
	{
	loop_vars = arg_loop_vars;
	body = nullptr;

	if ( e->GetType()->Tag() == TYPE_TABLE )
		{
		const auto& indices = e->GetType()->AsTableType()->IndexTypes();

		if ( static_cast<int>(indices.size()) != loop_vars->length() )
			{
			e->Error("wrong index size");
			return;
			}

		for ( auto i = 0u; i < indices.size(); i++ )
			{
			const auto& ind_type = indices[i];
			const auto& lv = (*loop_vars)[i];
			const auto& lvt = lv->GetType();

			if ( lvt )
				{
				if ( ! same_type(lvt.get(), ind_type.get()) )
					lvt->Error("type clash in iteration", ind_type.get());
				}

			else
				{
				add_local({NewRef{}, lv}, ind_type, INIT_NONE,
				          nullptr, nullptr, VAR_REGULAR);
				}
			}
		}

	else if ( e->GetType()->Tag() == TYPE_VECTOR )
		{
		if ( loop_vars->length() != 1 )
			{
			e->Error("iterating over a vector requires only a single index type");
			return;
			}

		const auto& t = (*loop_vars)[0]->GetType();

		if ( ! t )
			add_local({NewRef{}, (*loop_vars)[0]}, base_type(TYPE_COUNT),
						INIT_NONE, nullptr, nullptr, VAR_REGULAR);

		else if ( ! IsIntegral(t->Tag()) )
			{
			e->Error("vector index in \"for\" loop must be integral");
			return;
			}
		}

	else if ( e->GetType()->Tag() == TYPE_STRING )
		{
		if ( loop_vars->length() != 1 )
			{
			e->Error("iterating over a string requires only a single index type");
			return;
			}

		const auto& t = (*loop_vars)[0]->GetType();

		if ( ! t )
			add_local({NewRef{}, (*loop_vars)[0]},
					base_type(TYPE_STRING),
					INIT_NONE, nullptr, nullptr, VAR_REGULAR);

		else if ( t->Tag() != TYPE_STRING )
			{
			e->Error("string index in \"for\" loop must be string");
			return;
			}
		}
	else
		e->Error("target to iterate over must be a table, set, vector, or string");
	}

ForStmt::ForStmt(id_list* arg_loop_vars,
                 IntrusivePtr<Expr> loop_expr, IntrusivePtr<ID> val_var)
	: ForStmt(arg_loop_vars, std::move(loop_expr))
	{
	value_var = std::move(val_var);

	if ( e->GetType()->IsTable() )
		{
		const auto& yield_type = e->GetType()->AsTableType()->Yield();

		// Verify value_vars type if its already been defined
		if ( value_var->GetType() )
			{
			if ( ! same_type(value_var->GetType().get(), yield_type.get()) )
				value_var->GetType()->Error("type clash in iteration", yield_type.get());
			}
		else
			{
			add_local(value_var, yield_type, INIT_NONE, nullptr, nullptr, VAR_REGULAR);
			}
		}
	else
		e->Error("key value for loops only support iteration over tables");
	}

ForStmt::~ForStmt()
	{
	for ( const auto& var : *loop_vars )
		Unref(var);
	delete loop_vars;
	}

IntrusivePtr<Val> ForStmt::DoExec(Frame* f, Val* v, stmt_flow_type& flow) const
	{
	IntrusivePtr<Val> ret;

	if ( v->GetType()->Tag() == TYPE_TABLE )
		{
		TableVal* tv = v->AsTableVal();
		const PDict<TableEntryVal>* loop_vals = tv->AsTable();

		if ( ! loop_vals->Length() )
			return nullptr;

		HashKey* k;
		TableEntryVal* current_tev;
		IterCookie* c = loop_vals->InitForIteration();
		while ( (current_tev = loop_vals->NextEntry(k, c)) )
			{
			auto ind_lv = tv->RecoverIndex(k);
			delete k;

			if ( value_var )
				f->SetElement(value_var.get(), current_tev->Value()->Ref());

			for ( int i = 0; i < ind_lv->Length(); i++ )
				f->SetElement((*loop_vars)[i], ind_lv->Idx(i)->Ref());

			flow = FLOW_NEXT;

			try
				{
				ret = body->Exec(f, flow);
				}
			catch ( InterpreterException& )
				{
				loop_vals->StopIteration(c);
				throw;
				}

			if ( flow == FLOW_BREAK || flow == FLOW_RETURN )
				{
				// If we broke or returned from inside a for loop,
				// the cookie may still exist.
				loop_vals->StopIteration(c);
				break;
				}
			}
		}

	else if ( v->GetType()->Tag() == TYPE_VECTOR )
		{
		VectorVal* vv = v->AsVectorVal();

		for ( auto i = 0u; i <= vv->Size(); ++i )
			{
			// Skip unassigned vector indices.
			if ( ! vv->Lookup(i) )
				continue;

			// Set the loop variable to the current index, and make
			// another pass over the loop body.
			f->SetElement((*loop_vars)[0], val_mgr->Count(i).release());
			flow = FLOW_NEXT;
			ret = body->Exec(f, flow);

			if ( flow == FLOW_BREAK || flow == FLOW_RETURN )
				break;
			}
		}
	else if ( v->GetType()->Tag() == TYPE_STRING )
		{
		StringVal* sval = v->AsStringVal();

		for ( int i = 0; i < sval->Len(); ++i )
			{
			f->SetElement((*loop_vars)[0],
					new StringVal(1, (const char*) sval->Bytes() + i));
			flow = FLOW_NEXT;
			ret = body->Exec(f, flow);

			if ( flow == FLOW_BREAK || flow == FLOW_RETURN )
				break;
			}
		}

	else
		e->Error("Invalid type in for-loop execution");

	if ( flow == FLOW_LOOP )
		flow = FLOW_NEXT;	// last iteration exited with a "next"

	if ( flow == FLOW_BREAK )
		flow = FLOW_NEXT;	// we've now finished the "break"

	return ret;
	}

bool ForStmt::IsPure() const
	{
	return e->IsPure() && body->IsPure();
	}

void ForStmt::Describe(ODesc* d) const
	{
	Stmt::Describe(d);

	if ( d->IsReadable() )
		d->Add("(");

	if ( loop_vars->length() )
		d->Add("[");

	loop_over_list(*loop_vars, i)
		{
		(*loop_vars)[i]->Describe(d);
		if ( i > 0 )
			d->Add(",");
		}

	if ( loop_vars->length() )
		d->Add("]");

	if ( d->IsReadable() )
		d->Add(" in ");

	e->Describe(d);

	if ( d->IsReadable() )
		d->Add(")");

	d->SP();

	d->PushIndent();
	body->AccessStats(d);
	body->Describe(d);
	d->PopIndent();
	}

TraversalCode ForStmt::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreStmt(this);
	HANDLE_TC_STMT_PRE(tc);

	for ( const auto& var : *loop_vars )
		{
		tc = var->Traverse(cb);
		HANDLE_TC_STMT_PRE(tc);
		}

	tc = LoopExpr()->Traverse(cb);
	HANDLE_TC_STMT_PRE(tc);

	tc = LoopBody()->Traverse(cb);
	HANDLE_TC_STMT_PRE(tc);

	tc = cb->PostStmt(this);
	HANDLE_TC_STMT_POST(tc);
	}

IntrusivePtr<Val> NextStmt::Exec(Frame* /* f */, stmt_flow_type& flow) const
	{
	RegisterAccess();
	flow = FLOW_LOOP;
	return nullptr;
	}

bool NextStmt::IsPure() const
	{
	return true;
	}

void NextStmt::Describe(ODesc* d) const
	{
	Stmt::Describe(d);
	Stmt::DescribeDone(d);
	}

TraversalCode NextStmt::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreStmt(this);
	HANDLE_TC_STMT_PRE(tc);

	tc = cb->PostStmt(this);
	HANDLE_TC_STMT_POST(tc);
	}

IntrusivePtr<Val> BreakStmt::Exec(Frame* /* f */, stmt_flow_type& flow) const
	{
	RegisterAccess();
	flow = FLOW_BREAK;
	return nullptr;
	}

bool BreakStmt::IsPure() const
	{
	return true;
	}

void BreakStmt::Describe(ODesc* d) const
	{
	Stmt::Describe(d);
	Stmt::DescribeDone(d);
	}

TraversalCode BreakStmt::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreStmt(this);
	HANDLE_TC_STMT_PRE(tc);

	tc = cb->PostStmt(this);
	HANDLE_TC_STMT_POST(tc);
	}

IntrusivePtr<Val> FallthroughStmt::Exec(Frame* /* f */, stmt_flow_type& flow) const
	{
	RegisterAccess();
	flow = FLOW_FALLTHROUGH;
	return nullptr;
	}

bool FallthroughStmt::IsPure() const
	{
	return false;
	}

void FallthroughStmt::Describe(ODesc* d) const
	{
	Stmt::Describe(d);
	Stmt::DescribeDone(d);
	}

TraversalCode FallthroughStmt::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreStmt(this);
	HANDLE_TC_STMT_PRE(tc);

	tc = cb->PostStmt(this);
	HANDLE_TC_STMT_POST(tc);
	}

ReturnStmt::ReturnStmt(IntrusivePtr<Expr> arg_e)
	: ExprStmt(STMT_RETURN, std::move(arg_e))
	{
	Scope* s = current_scope();

	if ( ! s || ! s->ScopeID() )
		{
		Error("return statement outside of function/event");
		return;
		}

	FuncType* ft = s->ScopeID()->GetType()->AsFuncType();
	const auto& yt = ft->Yield();

	if ( s->ScopeID()->DoInferReturnType() )
		{
		if ( e )
			{
			ft->SetYieldType(e->GetType());
			s->ScopeID()->SetInferReturnType(false);
			}
		}

	else if ( ! yt || yt->Tag() == TYPE_VOID )
		{
		if ( e )
			Error("return statement cannot have an expression");
		}

	else if ( ! e )
		{
		if ( ft->Flavor() != FUNC_FLAVOR_HOOK )
			Error("return statement needs expression");
		}

	else
		{
		auto promoted_e = check_and_promote_expr(e.get(), yt.get());

		if ( promoted_e )
			e = std::move(promoted_e);
		}
	}

IntrusivePtr<Val> ReturnStmt::Exec(Frame* f, stmt_flow_type& flow) const
	{
	RegisterAccess();
	flow = FLOW_RETURN;

	if ( e )
		return e->Eval(f);
	else
		return nullptr;
	}

void ReturnStmt::Describe(ODesc* d) const
	{
	Stmt::Describe(d);
	if ( ! d->IsReadable() )
		d->Add(e != nullptr);

	if ( e )
		{
		if ( ! d->IsBinary() )
			d->Add("(");
		e->Describe(d);
		if ( ! d->IsBinary() )
			d->Add(")");
		}

	DescribeDone(d);
	}

StmtList::StmtList() : Stmt(STMT_LIST)
	{
	}

StmtList::~StmtList()
	{
	for ( const auto& stmt : stmts )
		Unref(stmt);
	}

IntrusivePtr<Val> StmtList::Exec(Frame* f, stmt_flow_type& flow) const
	{
	RegisterAccess();
	flow = FLOW_NEXT;

	for ( const auto& stmt : stmts )
		{
		f->SetNextStmt(stmt);

		if ( ! pre_execute_stmt(stmt, f) )
			{ // ### Abort or something
			}

		auto result = stmt->Exec(f, flow);

		if ( ! post_execute_stmt(stmt, f, result.get(), &flow) )
			{ // ### Abort or something
			}

		if ( flow != FLOW_NEXT || result || f->HasDelayed() )
			return result;
		}

	return nullptr;
	}

bool StmtList::IsPure() const
	{
	for ( const auto& stmt : stmts )
		if ( ! stmt->IsPure() )
			return false;
	return true;
	}

void StmtList::Describe(ODesc* d) const
	{
	if ( ! d->IsReadable() )
		{
		AddTag(d);
		d->AddCount(stmts.length());
		}

	if ( stmts.length() == 0 )
		DescribeDone(d);

	else
		{
		if ( ! d->IsBinary() )
			{
			d->Add("{ ");
			d->NL();
			}

		for ( const auto& stmt : stmts )
			{
			stmt->Describe(d);
			d->NL();
			}

		if ( ! d->IsBinary() )
			d->Add("}");
		}
	}

TraversalCode StmtList::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreStmt(this);
	HANDLE_TC_STMT_PRE(tc);

	for ( const auto& stmt : stmts )
		{
		tc = stmt->Traverse(cb);
		HANDLE_TC_STMT_PRE(tc);
		}

	tc = cb->PostStmt(this);
	HANDLE_TC_STMT_POST(tc);
	}

IntrusivePtr<Val> EventBodyList::Exec(Frame* f, stmt_flow_type& flow) const
	{
	RegisterAccess();
	flow = FLOW_NEXT;

	for ( const auto& stmt : stmts )
		{
		f->SetNextStmt(stmt);

		// Ignore the return value, since there shouldn't be
		// any; and ignore the flow, since we still execute
		// all of the event bodies even if one of them does
		// a FLOW_RETURN.
		if ( ! pre_execute_stmt(stmt, f) )
			{ // ### Abort or something
			}

		auto result = stmt->Exec(f, flow);

		if ( ! post_execute_stmt(stmt, f, result.get(), &flow) )
			{ // ### Abort or something
			}
		}

	// Simulate a return so the hooks operate properly.
	stmt_flow_type ft = FLOW_RETURN;
	(void) post_execute_stmt(f->GetNextStmt(), f, nullptr, &ft);

	return nullptr;
	}

void EventBodyList::Describe(ODesc* d) const
	{
	if ( d->IsReadable() && stmts.length() > 0 )
		{
		for ( const auto& stmt : stmts )
			{
			if ( ! d->IsBinary() )
				{
				d->Add("{");
				d->PushIndent();
				stmt->AccessStats(d);
				}

			stmt->Describe(d);

			if ( ! d->IsBinary() )
				{
				d->Add("}");
				d->PopIndent();
				}
			}
		}

	else
		StmtList::Describe(d);
	}

InitStmt::InitStmt(id_list* arg_inits) : Stmt(STMT_INIT)
	{
	inits = arg_inits;
	if ( arg_inits && arg_inits->length() )
		SetLocationInfo((*arg_inits)[0]->GetLocationInfo());
	}

InitStmt::~InitStmt()
	{
	for ( const auto& init : *inits )
		Unref(init);

	delete inits;
	}

IntrusivePtr<Val> InitStmt::Exec(Frame* f, stmt_flow_type& flow) const
	{
	RegisterAccess();
	flow = FLOW_NEXT;

	for ( const auto& aggr : *inits )
		{
		const auto& t = aggr->GetType();

		Val* v = nullptr;

		switch ( t->Tag() ) {
		case TYPE_RECORD:
			v = new RecordVal(t->AsRecordType());
			break;
		case TYPE_VECTOR:
			v = new VectorVal(cast_intrusive<VectorType>(t));
			break;
		case TYPE_TABLE:
			v = new TableVal(cast_intrusive<TableType>(t), {NewRef{}, aggr->Attrs()});
			break;
		default:
			break;
		}

		f->SetElement(aggr, v);
		}

	return nullptr;
	}

void InitStmt::Describe(ODesc* d) const
	{
	AddTag(d);

	if ( ! d->IsReadable() )
		d->AddCount(inits->length());

	loop_over_list(*inits, i)
		{
		if ( ! d->IsBinary() && i > 0 )
			d->AddSP(",");

		(*inits)[i]->Describe(d);
		}

	DescribeDone(d);
	}

TraversalCode InitStmt::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreStmt(this);
	HANDLE_TC_STMT_PRE(tc);

	for ( const auto& init : *inits )
		{
		tc = init->Traverse(cb);
		HANDLE_TC_STMT_PRE(tc);
		}

	tc = cb->PostStmt(this);
	HANDLE_TC_STMT_POST(tc);
	}

IntrusivePtr<Val> NullStmt::Exec(Frame* /* f */, stmt_flow_type& flow) const
	{
	RegisterAccess();
	flow = FLOW_NEXT;
	return nullptr;
	}

bool NullStmt::IsPure() const
	{
	return true;
	}

void NullStmt::Describe(ODesc* d) const
	{
	if ( d->IsReadable() )
		DescribeDone(d);
	else
		AddTag(d);
	}

TraversalCode NullStmt::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreStmt(this);
	HANDLE_TC_STMT_PRE(tc);

	tc = cb->PostStmt(this);
	HANDLE_TC_STMT_POST(tc);
	}

WhenStmt::WhenStmt(IntrusivePtr<Expr> arg_cond,
                   IntrusivePtr<Stmt> arg_s1, IntrusivePtr<Stmt> arg_s2,
                   IntrusivePtr<Expr> arg_timeout, bool arg_is_return)
	: Stmt(STMT_WHEN),
	  cond(std::move(arg_cond)), s1(std::move(arg_s1)), s2(std::move(arg_s2)),
	  timeout(std::move(arg_timeout)), is_return(arg_is_return)
	{
	assert(cond);
	assert(s1);

	if ( ! cond->IsError() && ! IsBool(cond->GetType()->Tag()) )
		cond->Error("conditional in test must be boolean");

	if ( timeout )
		{
		if ( timeout->IsError() )
			return;

		TypeTag bt = timeout->GetType()->Tag();
		if ( bt != TYPE_TIME && bt != TYPE_INTERVAL )
			cond->Error("when timeout requires a time or time interval");
		}
	}

WhenStmt::~WhenStmt() = default;

IntrusivePtr<Val> WhenStmt::Exec(Frame* f, stmt_flow_type& flow) const
	{
	RegisterAccess();
	flow = FLOW_NEXT;

	// The new trigger object will take care of its own deletion.
	new trigger::Trigger(IntrusivePtr{cond}.release(),
	                     IntrusivePtr{s1}.release(),
	                     IntrusivePtr{s2}.release(),
	                     IntrusivePtr{timeout}.release(),
	                     f, is_return, location);
	return nullptr;
	}

bool WhenStmt::IsPure() const
	{
	return cond->IsPure() && s1->IsPure() && (! s2 || s2->IsPure());
	}

void WhenStmt::Describe(ODesc* d) const
	{
	Stmt::Describe(d);

	if ( d->IsReadable() )
		d->Add("(");

	cond->Describe(d);

	if ( d->IsReadable() )
		d->Add(")");

	d->SP();
	d->PushIndent();
	s1->AccessStats(d);
	s1->Describe(d);
	d->PopIndent();

	if ( s2 )
		{
		if ( d->IsReadable() )
			{
			d->SP();
			d->Add("timeout");
			d->SP();
			timeout->Describe(d);
			d->SP();
			d->PushIndent();
			s2->AccessStats(d);
			s2->Describe(d);
			d->PopIndent();
			}
		else
			s2->Describe(d);
		}
	}

TraversalCode WhenStmt::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreStmt(this);
	HANDLE_TC_STMT_PRE(tc);

	tc = cond->Traverse(cb);
	HANDLE_TC_STMT_PRE(tc);

	tc = s1->Traverse(cb);
	HANDLE_TC_STMT_PRE(tc);

	if ( s2 )
		{
		tc = s2->Traverse(cb);
		HANDLE_TC_STMT_PRE(tc);
		}

	tc = cb->PostStmt(this);
	HANDLE_TC_STMT_POST(tc);
	}
