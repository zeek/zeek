#include <cstdio>
#include <string>
#include <list>
#include "ID.h"
#include "BroDocObj.h"

BroDocObj::BroDocObj(const ID* id, std::list<std::string>*& reST)
    {
    broID = id;
    reST_doc_strings = reST;
    reST = 0;
    }

BroDocObj::~BroDocObj()
    {
    delete reST_doc_strings;
    }

void BroDocObj::WriteReST(FILE* file) const
    {
    if ( reST_doc_strings )
        {
        std::list<std::string>::const_iterator it;
        for ( it = reST_doc_strings->begin();
              it != reST_doc_strings->end(); ++it)
            fprintf(file, "%s\n", it->c_str());
        }

    ODesc desc;
    desc.SetQuotes(1);
    broID->DescribeReST(&desc);
    fprintf(file, "%s\n\n", desc.Description());
    }
