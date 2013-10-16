#include <cstdio>
#include <string>
#include <list>
#include "ID.h"
#include "BroDocObj.h"

map<string, BroDocObj*> doc_ids = map<string, BroDocObj*>();

BroDocObj* BroDocObj::last = 0;

BroDocObj::BroDocObj(const ID* id, std::list<std::string>*& reST,
			bool is_fake)
	{
	last = this;
	broID = id;
	reST_doc_strings = reST;
	reST = 0;
	is_fake_id = is_fake;
	use_role = 0;
	FormulateShortDesc();
	doc_ids[id->Name()] = this;
	}

BroDocObj::~BroDocObj()
	{
	if ( reST_doc_strings )
		delete reST_doc_strings;

	if ( is_fake_id )
		delete broID;
	}

void BroDocObj::WriteReSTCompact(FILE* file, int max_col) const
	{
	ODesc desc;
	desc.SetQuotes(1);
	broID->DescribeReSTShort(&desc);

	fprintf(file, "%s", desc.Description());

	std::list<std::string>::const_iterator it;

	for ( it = short_desc.begin(); it != short_desc.end(); ++it )
		{
		int start_col;

		if ( it == short_desc.begin() )
			start_col = max_col - desc.Len() + 1;
		else
			{
			start_col = max_col + 1;
			fprintf(file, "\n");
			}

		for ( int i = 0; i < start_col; ++i )
			fprintf(file, " ");

		fprintf(file, "%s", it->c_str());
		}
	}

int BroDocObj::LongestShortDescLen() const
	{
	size_t max = 0;

	std::list<std::string>::const_iterator it;

	for ( it = short_desc.begin(); it != short_desc.end(); ++it )
		{
		if ( it->size() > max )
			max = it->size();
		}

	return max;
	}

static size_t end_of_first_sentence(string s)
	{
	size_t rval = 0;

	while ( (rval = s.find_first_of('.', rval)) != string::npos )
		{
		if ( rval == s.size() - 1 )
			// Period is at end of string.
			return rval;

		if ( isspace(s[rval + 1]) )
			// Period has a space after it.
			return rval;

		// Period has some non-space character after it, keep looking.
		++rval;
		}

	return rval;
	}

void BroDocObj::FormulateShortDesc()
	{
	if ( ! reST_doc_strings )
		return;

	short_desc.clear();
	std::list<std::string>::const_iterator it;

	for ( it = reST_doc_strings->begin();
		it != reST_doc_strings->end(); ++it )
		{
		// The short description stops at the first sentence or the
		// first empty comment.
		size_t end = end_of_first_sentence(*it);

		if ( end == string::npos )
			{
			std::string::const_iterator s;
			bool empty = true;

			for ( s = it->begin(); s != it->end(); ++s )
				{
				if ( *s != ' ' && *s != '\t' && *s != '\n' && *s != '\r' )
					{
					empty = false;
					short_desc.push_back(*it);
					break;
					}
				}

			if ( empty )
				break;
			}
		else
			{
			short_desc.push_back(it->substr(0, end + 1));
			break;
			}
		}
	}

void BroDocObj::WriteReST(FILE* file) const
	{
	int indent_spaces = 3;
	ODesc desc;
	desc.SetIndentSpaces(indent_spaces);
	desc.SetQuotes(1);

	broID->DescribeReST(&desc, use_role);

	fprintf(file, "%s", desc.Description());

	if ( HasDocumentation() )
		{
		fprintf(file, "\n");
		std::list<std::string>::const_iterator it;

		for ( it = reST_doc_strings->begin();
			it != reST_doc_strings->end(); ++it)
			{
			for ( int i = 0; i < indent_spaces; ++i )
				fprintf(file, " ");

			fprintf(file, "%s\n", it->c_str());
			}
		}

	fprintf(file, "\n");
	}

int BroDocObj::ColumnSize() const
	{
	ODesc desc;
	desc.SetQuotes(1);
	broID->DescribeReSTShort(&desc);
	return desc.Len();
	}

bool BroDocObj::IsPublicAPI() const
	{
	return (broID->Scope() == SCOPE_GLOBAL) ||
		(broID->Scope() == SCOPE_MODULE && broID->IsExport());
	}

void BroDocObj::Combine(const BroDocObj* o)
	{
	if ( o->reST_doc_strings )
		{
		if ( ! reST_doc_strings )
			reST_doc_strings = new std::list<std::string>();

		reST_doc_strings->splice(reST_doc_strings->end(),
			*(o->reST_doc_strings));
		}

	delete o;
	FormulateShortDesc();
	}
