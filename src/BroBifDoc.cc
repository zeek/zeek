#include <cstdio>
#include <string>
#include <list>

#include "BroDoc.h"
#include "BroBifDoc.h"

BroBifDoc::BroBifDoc(const std::string& sourcename) : BroDoc(sourcename)
    {
    }

//TODO: this needs to do something different than parent class's version
void BroBifDoc::WriteDocFile() const
    {
    BroDoc::WriteDocFile();
    }
