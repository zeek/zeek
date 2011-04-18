#ifndef brobifdoc_h
#define brobifdoc_h

#include <cstdio>
#include <string>
#include <list>

#include "BroDoc.h"

class BroBifDoc : public BroDoc {
public:
	BroBifDoc(const std::string& sourcename);
	virtual ~BroBifDoc()	{ }

	void WriteDocFile() const;
};

#endif
