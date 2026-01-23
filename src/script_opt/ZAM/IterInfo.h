// See the file "COPYING" in the main distribution directory for copyright.

// Classes to support ZAM for-loop iterations.

#pragma once

#include "zeek/Dict.h"
#include "zeek/Val.h"
#include "zeek/ZeekString.h"
#include "zeek/script_opt/ZAM/ZInstAux.h"

namespace zeek::detail {

// Class for iterating over the elements of a table.  Requires some care
// because the dictionary iterators need to be destructed when done.

class TableIterInfo {
public:
    // Empty constructor for a simple version that initializes all the
    // member variables via BeginLoop(). Helpful for supporting recursive
    // functions that include table iterations.
    TableIterInfo() = default;

    // Version that populates the fixed fields up front, with the
    // dynamic ones being done with SetLoopVars().
    TableIterInfo(const std::vector<TypePtr>* _loop_var_types, const std::vector<bool>* _lvt_is_managed,
                  TypePtr _value_var_type) {
        SetIterInfo(_loop_var_types, _lvt_is_managed, std::move(_value_var_type));
    }

    // Sets the fixed fields.
    void SetIterInfo(const std::vector<TypePtr>* _loop_var_types, const std::vector<bool>* _lvt_is_managed,
                     TypePtr _value_var_type) {
        loop_var_types = _loop_var_types;
        lvt_is_managed = _lvt_is_managed;
        value_var_type = std::move(_value_var_type);
    }

    // We do, however, want to make sure that when we go out of scope,
    // if we have any pending iterators we clear them.
    ~TableIterInfo() { Clear(); }

    // Start looping over the elements of the given table.  "aux"
    // provides information about the index variables, their types,
    // and the type of the value variable (if any).
    void BeginLoop(TableValPtr _tv, ZVal* frame, ZInstAux* aux) {
        tv = std::move(_tv);

        // Clear loop_vars to prevent unbounded growth when TableIterInfo is reused
        loop_vars.clear();

        for ( auto lv : aux->loop_vars )
            if ( lv < 0 )
                loop_vars.push_back(nullptr);
            else
                loop_vars.push_back(&frame[lv]);

        SetIterInfo(&aux->types, &aux->is_managed, aux->value_var_type);

        PrimeIter();
    }

    void BeginLoop(TableValPtr _tv, std::vector<ZVal*> _loop_vars) {
        tv = std::move(_tv);
        loop_vars = std::move(_loop_vars);
        PrimeIter();
    }

    void PrimeIter() {
        auto tvd = tv->AsTable();
        tbl_iter = tvd->begin();
        tbl_end = tvd->end();
    }

    // True if we're done iterating, false if not.
    bool IsDoneIterating() const { return *tbl_iter == *tbl_end; }

    // Indicates that the current iteration is finished.
    void IterFinished() { ++*tbl_iter; }

    // Performs the next iteration (assuming IsDoneIterating() returned
    // false), assigning to the index variables.
    void NextIter() {
        auto ind_lv = tv->RecreateIndex(*(*tbl_iter)->GetHashKey());
        for ( int i = 0; i < ind_lv->Length(); ++i ) {
            auto lv = loop_vars[i];
            if ( ! lv )
                continue;

            ValPtr ind_lv_p = ind_lv->Idx(i);
            if ( (*lvt_is_managed)[i] )
                ZVal::DeleteManagedType(*lv);
            *lv = ZVal(ind_lv_p, (*loop_var_types)[i]);
        }

        IterFinished();
    }

    // For the current iteration, returns the corresponding value.
    ZVal IterValue() {
        auto tev = (*tbl_iter)->value;
        return {tev->GetVal(), value_var_type};
    }

    // Called upon finishing the iteration.
    void EndIter() { Clear(); }

    // Called to explicitly clear any iteration state.
    void Clear() {
        tbl_iter = std::nullopt;
        tbl_end = std::nullopt;
    }

private:
    TableValPtr tv = nullptr;

    std::vector<ZVal*> loop_vars;
    const std::vector<TypePtr>* loop_var_types = nullptr;
    const std::vector<bool>* lvt_is_managed = nullptr;
    TypePtr value_var_type;

    std::optional<DictIterator<TableEntryVal>> tbl_iter;
    std::optional<DictIterator<TableEntryVal>> tbl_end;
};

// Class for simple step-wise iteration across an integer range.
// Suitable for iterating over vectors or strings.

class StepIterInfo {
public:
    // We do some cycle-squeezing by not having a constructor to
    // initialize our member variables, since we impose a discipline
    // that any use of the object starts with InitLoop().  That lets
    // us use quasi-static objects for non-recursive functions.

    // Initializes for looping over the elements of a raw vector.
    void InitLoop(const std::vector<std::optional<ZVal>>* _vv) {
        vv = _vv;
        n = vv->size();
        iter = 0;
    }

    // Initializes for looping over the elements of a raw string.
    void InitLoop(const String* _s) {
        s = _s;
        n = s->Len();
        iter = 0;
    }

    // True if we're done iterating, false if not.
    bool IsDoneIterating() const { return iter >= n; }

    // Indicates that the current iteration is finished.
    void IterFinished() { ++iter; }

    // Counter of where we are in the iteration.
    zeek_uint_t iter; // initialized to 0 at start of loop
    zeek_uint_t n;    // we loop from 0 ... n-1

    // The low-level value we're iterating over.
    const std::vector<std::optional<ZVal>>* vv;
    const String* s;
};

} // namespace zeek::detail
