#include <cstdio>
#include <string>
#include <list>
#include "ID.h"
#include "BroDocObj.h"

BroDocObj::BroDocObj(const ID* id, std::list<std::string>*& reST,
                     bool is_fake)
	{
	broID = id;
	reST_doc_strings = reST;
	reST = 0;
	is_fake_id = is_fake;
	use_role = 0;
	}

BroDocObj::~BroDocObj()
	{
	delete reST_doc_strings;
	if ( is_fake_id ) delete broID;
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
