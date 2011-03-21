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
	}

BroDocObj::~BroDocObj()
	{
	delete reST_doc_strings;
	if ( is_fake_id ) delete broID;
	}

void BroDocObj::WriteReST(FILE* file) const
	{
	ODesc desc;
	desc.SetIndentSpaces(4);
	desc.SetQuotes(1);
	broID->DescribeReST(&desc);
	fprintf(file, "%s\n", desc.Description());

	if ( HasDocumentation() )
		{
		fprintf(file, "\n");
		std::list<std::string>::const_iterator it;
		for ( it = reST_doc_strings->begin();
		      it != reST_doc_strings->end(); ++it)
			fprintf(file, "    %s\n", it->c_str());
		}

	fprintf(file, "\n");
	}
