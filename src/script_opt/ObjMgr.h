// See the file "COPYING" in the main distribution directory for copyright.

// Classes for tracking a collection of "const Obj*" pointers for memory
// management purposes. In particular, script optimization often has to
// deal with bare const pointers (because the traversal infrastructure is
// oriented around those, and because of the need to track AST nodes in
// containers, which don't support IntrusivePtr's).  During optimization
// AST nodes are both created and replaced/discarded, which can lead to
// mis-aliasing of old instances of those pointers with new ones.
//
// Note, this functionality is only required for data structures with
// lifetimes that span AST-rewriting steps. Those that are germane only
// for a fixed AST instance (such as ProfileFunc and management of
// confluence blocks) don't need to use these.

#pragma once

#include <unordered_map>

#include "zeek/IntrusivePtr.h"
#include "zeek/Obj.h"

namespace zeek::detail {

// A class that keeps a const Obj* pointer live - used to isolate instances
// of const_cast.

class ObjWrapper {
public:
    ObjWrapper(const Obj* wrappee) {
        auto non_const_w = const_cast<Obj*>(wrappee);
        wrappee_ptr = {NewRef{}, non_const_w};
    }

private:
    IntrusivePtr<Obj> wrappee_ptr;
};

// Manages a bunch of const Obj* pointers collectively.

class ObjMgr {
public:
    void AddObj(const Obj* o) {
        if ( ! obj_collection.contains(o) )
            obj_collection.emplace(std::pair<const Obj*, ObjWrapper>{o, ObjWrapper(o)});
    }

private:
    std::unordered_map<const Obj*, ObjWrapper> obj_collection;
};

} // namespace zeek::detail
