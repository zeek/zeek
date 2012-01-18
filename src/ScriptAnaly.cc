// See the file "COPYING" in the main distribution directory for copyright.

#include "Dict.h"
#include "Expr.h"
#include "Traverse.h"
#include "ScriptAnaly.h"

typedef const char cchar;
declare(PDict, cchar);


class FindNoteCallback : public TraversalCallback {
public:
	FindNoteCallback()	{ note_expr = 0; }

	virtual TraversalCode PreExpr(const Expr* e);

	Expr* note_expr;
};

TraversalCode FindNoteCallback::PreExpr(const Expr* e)
	{
	if ( e->Tag() == EXPR_FIELD_ASSIGN )
		{
		const FieldAssignExpr* fae =
			dynamic_cast<const FieldAssignExpr*>(e);

		if ( ! streq(fae->FieldName(), "note") )
			return TC_CONTINUE;

		note_expr = fae->Op();
		return TC_ABORTALL;
		}

	return TC_CONTINUE;
	}


class NoticeCallback : public TraversalCallback {
public:
	virtual TraversalCode PreExpr(const Expr* e);

	PDict(cchar) notices;
};

TraversalCode NoticeCallback::PreExpr(const Expr* e)
	{
	if ( e->Tag() != EXPR_CALL )
		return TC_CONTINUE;

	const CallExpr* ce = dynamic_cast<const CallExpr*>(e);

	if ( ce->Func()->Tag() != EXPR_NAME ||
	     ! streq(((NameExpr*) ce->Func())->Id()->Name(), "NOTICE") )
		return TC_CONTINUE;

	FindNoteCallback fnc;
	ce->Traverse(&fnc);
	if ( fnc.note_expr )
		{
		ODesc d;
		fnc.note_expr->Describe(&d);
		if ( ! notices.Lookup(d.Description()) )
			{
			const char* desc = strdup(d.Description());
			notices.Insert(desc, desc);
			}
		}

	return TC_CONTINUE;
	}


void notice_analysis()
	{
	NoticeCallback cb;
	traverse_all(&cb);

	const cchar* notice = 0;
	IterCookie* iter = cb.notices.InitForIteration();

	while ( (notice = cb.notices.NextEntry(iter)) )
		printf("Found NOTICE: %s\n", notice);
	}
