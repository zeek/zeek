#ifndef pac_withinput_h
#define pac_withinput_h

#include "pac_datadep.h"
#include "pac_decl.h"
#include "pac_field.h"

class WithInputField : public Field, public Evaluatable
{
public:
	WithInputField(ID* id, Type *type, InputBuffer* input);
	virtual ~WithInputField();

	InputBuffer *input() const	{ return input_; }

	void Prepare(Env* env);

	// void GenPubDecls(Output* out, Env* env);
	// void GenPrivDecls(Output* out, Env* env);

	// void GenInitCode(Output* out, Env* env);
	// void GenCleanUpCode(Output* out, Env* env);

	void GenParseCode(Output* out, Env* env);

	// Instantiate the Evaluatable interface
	void GenEval(Output* out, Env* env);

	bool RequiresAnalyzerContext() const;

protected:
	bool DoTraverse(DataDepVisitor *visitor);

protected:
	InputBuffer *input_;
};

#endif  // pac_withinput_h
