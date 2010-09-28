#include "pac_exttype.h"
#include "pac_id.h"
#include "pac_output.h"
#include "pac_regex.h"
#include "pac_type.h"

// Depends on the regular expression library we are using
const char *RegEx::kREMatcherType = "RegExMatcher";
const char *RegEx::kMatchPrefix = "MatchPrefix";

string escape_char(const string &s)
	{
	char buf[s.length() * 2 + 1];
	int j = 0;
	for ( int i = 0; i < (int) s.length(); ++i )
		{
		if ( s[i] == '\\' )
			{
			if ( i + 1 < (int) s.length() ) 
				{
				buf[j++] = '\\';
				if ( s[i+1] == '/' )
					buf[j-1] = s[++i];
				else if ( s[i+1] == '/' || s[i+1] == '\\' || s[i+1] == '"' )
					buf[j++] = s[++i];
				else
					buf[j++] = '\\';
				}
			}
		else if ( s[i] == '"' )
			{
			buf[j++] = '\\';
			buf[j++] = '"';
			}
		else
			{
			buf[j++] = s[i];
			}
		}

	buf[j++] = '\0';

	return string(buf);
	}

RegEx::RegEx(const string &s)
	{
	str_ = escape_char(s);
	string prefix = strfmt("%s_re_", current_decl_id->Name());
	matcher_id_ = ID::NewAnonymousID(prefix);
	decl_ = new RegExDecl(this);
	}

RegEx::~RegEx()
	{
	}

RegExDecl::RegExDecl(RegEx *regex)
	: Decl(regex->matcher_id(), REGEX)
	{
	regex_ = regex;
	}

void RegExDecl::Prepare()
	{
	global_env()->AddID(id(), GLOBAL_VAR, extern_type_re_matcher);
	}

void RegExDecl::GenForwardDeclaration(Output *out_h)
	{
	out_h->println("extern %s %s;\n", 
		RegEx::kREMatcherType,
		global_env()->LValue(regex_->matcher_id()));
	}

void RegExDecl::GenCode(Output *out_h, Output *out_cc)
	{
	out_cc->println("%s %s(\"%s\");\n", 
		RegEx::kREMatcherType,
		global_env()->LValue(regex_->matcher_id()),
		regex_->str().c_str());
	}
