#include <cstdio>
#include <string>
#include <list>
#include "Obj.h"
#include "BroDocObj.h"

BroDocObj::BroDocObj(const BroObj* obj,
                     std::list<std::string>*& reST,
                     bool exported)
    {
    broObj = obj;
    isExported = exported;
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
    broObj->Describe(&desc);
    fprintf(file, "%s\n", desc.Description());
    }
