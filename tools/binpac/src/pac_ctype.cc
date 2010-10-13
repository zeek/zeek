#include "pac_ctype.h"

string CType::DeclareInstance(const string &var) const
	{
	return strfmt("%s %s", name().c_str(), var.c_str());
	}

string CType::DeclareConstReference(const string &var) const
	{
	return strfmt("%s const &%s", name().c_str(), var.c_str());
	}

string CType::DeclareConstPointer(const string &var) const
	{
	return strfmt("%s const *%s", name().c_str(), var.c_str());
	}

string CType::DeclarePointer(const string &var) const
	{
	return strfmt("%s *%s", name().c_str(), var.c_str());
	}
