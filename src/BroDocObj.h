#ifndef brodocobj_h
#define brodocobj_h

#include <cstdio>
#include <string>
#include <list>

#include "ID.h"

class BroDocObj {
public:
    /**
     * BroDocObj constructor
     * @param id a pointer to an identifier that is to be documented
     * @param reST a reference to a pointer of a list of strings that
              represent the reST documentation for the ID.  The pointer
              will be set to 0 after this constructor finishes.
     */
    BroDocObj(const ID* id, std::list<std::string>*& reST);

    /**
     * BroDocObj destructor
     * Deallocates the memory associated with the list of reST strings
     */
    ~BroDocObj();

    /**
     * writes the reST representation of this object which includes
     * 1) any of the "##" comments (stored internally in reST_doc_string)
     *    To make things easy, I think we should assume that the documenter
     *    writes their comments such that anything after ## is valid reST
     *    so that at parse time the ## is just stripped and the remainder
     *    is scheduled to be inserted as-is into the reST.
     *    TODO: prepare for some kind of filtering mechanism that transforms
     *    the reST as written into new reST before being written out.
     *    This allows for additional custom markup or macros when writing
     *    pure reST might be inconvenient.
     * 2) a reST friendly description of the ID
     *    Could be implemented similar to the ID::DescribeExtended(ODesc)
     *    expect with new directives/roles that we'll later teach to Sphinx
     *    via a "bro domain".
     * @param The (already opened) file to write the reST to.
     */
    void WriteReST(FILE* file) const;

    /**
     * Check whether this documentation is part of the public API
     * (The declaration was while in an export section).
     * @return true if the ID was declared in an export section, else false
     */
    bool IsPublicAPI() const { return broID->IsExport(); }

    /**
     * Return whether this object has documentation (## comments)
     * @return true if the ID has comments associated with it
     */
    bool HasDocumentation() const { return reST_doc_strings &&
                                           reST_doc_strings->size() > 0; }

protected:
    std::list<std::string>* reST_doc_strings;
    const ID* broID;

private:
};

#endif
