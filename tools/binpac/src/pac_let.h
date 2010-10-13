#ifndef pac_let_h
#define pac_let_h

#include "pac_decl.h"
#include "pac_field.h"

class LetField : public Field, Evaluatable
{
public:
	LetField(ID* arg_id, Type *type, Expr* arg_expr);
	~LetField();

	Expr *expr() const			{ return expr_; }

	void Prepare(Env* env);

	void GenInitCode(Output* out, Env* env);
	void GenParseCode(Output* out, Env* env);
	void GenEval(Output* out, Env* env);

	bool RequiresAnalyzerContext() const;

protected:
	bool DoTraverse(DataDepVisitor *visitor);

protected:
	Expr* expr_;
};

class LetDecl : public Decl, Evaluatable
{
public:
	LetDecl(ID *id, Type *type, Expr *expr);
	~LetDecl();

	Expr *expr() const	{ return expr_; }

	void Prepare();
	void GenForwardDeclaration(Output *out_h);
	void GenCode(Output *out_h, Output *out_cc);
	void GenEval(Output* out, Env* env);

private:
	Type *type_;
	Expr *expr_;
};

#endif  // pac_let_h
