#ifndef pac_regex_h
#define pac_regex_h

#include "pac_common.h"
#include "pac_decl.h"

class RegExDecl;

class RegEx : public Object
	{
public:
	RegEx(const string& str);
	~RegEx();

	const string& str() const { return str_; }
	ID* matcher_id() const { return matcher_id_; }

private:
	string str_;
	ID* matcher_id_;
	RegExDecl* decl_;

public:
	static const char* kREMatcherType;
	static const char* kMatchPrefix;
	};

class RegExDecl : public Decl
	{
public:
	RegExDecl(RegEx* regex);

	void Prepare() override;
	void GenForwardDeclaration(Output* out_h) override;
	void GenCode(Output* out_h, Output* out_cc) override;

private:
	RegEx* regex_;
	};

#endif // pac_regex_h
