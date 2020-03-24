// See the file "COPYING" in the main distribution directory for copyright.

#include "ScriptAnaly.h"
#include "Desc.h"
#include "Expr.h"
#include "Stmt.h"
#include "Traverse.h"

class FolderFinder : public TraversalCallback {
public:
	// TraversalCode PreExpr(const Expr*) override;
	TraversalCode PreExpr(const Expr*, const Expr*) override;
	TraversalCode PreExpr(const Expr*, const Expr*, const Expr*) override;

protected:
	void ReportFoldable(const Expr* e, const char* type);
};

void FolderFinder::ReportFoldable(const Expr* e, const char* type)
	{
	ODesc d;

	e->Describe(&d);
	d.SP();

	auto l = e->GetLocationInfo();
	if ( l )
		l->Describe(&d);
	else
		d.Add(" no location info");

	printf("foldable %s: %s\n", type, d.Description());
	}

TraversalCode FolderFinder::PreExpr(const Expr* expr, const Expr* op)
	{
	if ( op->IsConst() )
		ReportFoldable(expr, "unary");

	return TC_CONTINUE;
	}

TraversalCode FolderFinder::PreExpr(const Expr* expr, const Expr* op1, const Expr* op2)
	{
	if ( op1->IsConst() && op2->IsConst() )
		ReportFoldable(expr, "binary");

	return TC_CONTINUE;
	}


void analyze_function_ingredients(std::unique_ptr<function_ingredients>& fi)
	{
	FolderFinder cb;
	fi->body->Traverse(&cb);
	}
