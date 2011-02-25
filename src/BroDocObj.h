#ifndef brodocobj_h
#define brodocobj_h

#include <cstdio>
#include <string>
#include <list>

#include "Obj.h"

class BroDocObj {
public:
    /**
     * BroDocObj constructor
     * @param obj a pointer to a BroObj that is to be documented
     * @param reST a reference to a pointer of a list of strings that
              represent the reST documentation for the BroObj.  The pointer
              will be set to 0 after this constructor finishes.
     * @param exported whether the BroObj is declared in an export section
     */
    BroDocObj(const BroObj* obj, std::list<std::string>*& reST, bool exported);

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
     * 2) a reST friendly description of the BroObj
     *    Could be implemented similar to the virtual BroObj::Describe(ODesc)
     *    E.g. all subclasses will now need to implement a reSTDescribe(ODesc)
     *    so that they can describe themselves in terms of the custom reST
     *    directives/roles that we'll later teach to Sphinx via a "bro domain".
     *    ID's should be able to implement the reSTDescribe(ODesc) function
     *    such that their namespace and attributes are output as well.
     * @param The (already opened) file to write the reST to.
     */
    void WriteReST(FILE* file) const;

    /**
     * Check whether this documentation is part of the public API
     * (The BroObj declaration was while in an export section).
     * @return true if the BroObj was declared in an export section, else false
     */
    bool IsPublicAPI() const { return isExported; }

    /**
     * Return whether this object has documentation (## comments)
     * @return true if the BroObj has comments associated with it
     */
    bool HasDocumentation() const { return reST_doc_strings &&
                                           reST_doc_strings->size() > 0; }

protected:
    std::list<std::string>* reST_doc_strings;
    const BroObj* broObj;
    bool isExported;

private:
};

#endif
