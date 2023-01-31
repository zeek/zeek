#ifndef pac_withinput_h
#define pac_withinput_h

#include "pac_datadep.h"
#include "pac_decl.h"
#include "pac_field.h"

class WithInputField : public Field, public Evaluatable
	{
public:
	WithInputField(ID* id, Type* type, InputBuffer* input);
	~WithInputField() override;

	InputBuffer* input() const { return input_; }

	void Prepare(Env* env) override;

	// void GenPubDecls(Output* out, Env* env);
	// void GenPrivDecls(Output* out, Env* env);

	// void GenInitCode(Output* out, Env* env);
	// void GenCleanUpCode(Output* out, Env* env);

	void GenParseCode(Output* out, Env* env);

	// Instantiate the Evaluatable interface
	void GenEval(Output* out, Env* env) override;

	bool RequiresAnalyzerContext() const override;

protected:
	bool DoTraverse(DataDepVisitor* visitor) override;

protected:
	InputBuffer* input_;
	};

#endif // pac_withinput_h
