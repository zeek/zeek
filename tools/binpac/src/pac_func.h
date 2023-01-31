#ifndef pac_func_h
#define pac_func_h

#include "pac_analyzer.h"
#include "pac_decl.h"

class Function : public Object
	{
public:
	Function(ID* id, Type* type, ParamList* params);
	~Function();

	ID* id() const { return id_; }

	AnalyzerDecl* analyzer_decl() const { return analyzer_decl_; }
	void set_analyzer_decl(AnalyzerDecl* decl) { analyzer_decl_ = decl; }

	Expr* expr() const { return expr_; }
	void set_expr(Expr* expr) { expr_ = expr; }

	EmbeddedCode* code() const { return code_; }
	void set_code(EmbeddedCode* code) { code_ = code; }

	void Prepare(Env* env);
	void GenForwardDeclaration(Output* out_h);
	void GenCode(Output* out_h, Output* out_cc);

private:
	Env* env_;

	ID* id_;
	Type* type_;
	ParamList* params_;

	AnalyzerDecl* analyzer_decl_;

	Expr* expr_;
	EmbeddedCode* code_;
	};

class FuncDecl : public Decl
	{
public:
	FuncDecl(Function* function);
	~FuncDecl() override;

	Function* function() const { return function_; }

	void Prepare() override;
	void GenForwardDeclaration(Output* out_h) override;
	void GenCode(Output* out_h, Output* out_cc) override;

private:
	Function* function_;
	};

class AnalyzerFunction : public AnalyzerElement
	{
public:
	AnalyzerFunction(Function* function);

	Function* function() const { return function_; }

private:
	Function* function_;
	};

#endif // pac_func_h
