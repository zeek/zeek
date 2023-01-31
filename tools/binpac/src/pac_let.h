#ifndef pac_let_h
#define pac_let_h

#include "pac_decl.h"
#include "pac_field.h"

class LetField : public Field, Evaluatable
	{
public:
	LetField(ID* arg_id, Type* type, Expr* arg_expr);
	~LetField() override;

	Expr* expr() const { return expr_; }

	void Prepare(Env* env) override;

	void GenInitCode(Output* out, Env* env) override;
	void GenParseCode(Output* out, Env* env);
	void GenEval(Output* out, Env* env) override;

	bool RequiresAnalyzerContext() const override;

protected:
	bool DoTraverse(DataDepVisitor* visitor) override;

protected:
	Expr* expr_;
	};

class LetDecl : public Decl, Evaluatable
	{
public:
	LetDecl(ID* id, Type* type, Expr* expr);
	~LetDecl() override;

	Expr* expr() const { return expr_; }

	void Prepare() override;
	void GenForwardDeclaration(Output* out_h) override;
	void GenCode(Output* out_h, Output* out_cc) override;
	void GenEval(Output* out, Env* env) override;

private:
	Type* type_;
	Expr* expr_;
	};

#endif // pac_let_h
