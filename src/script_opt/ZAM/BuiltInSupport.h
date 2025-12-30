// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <optional>
#include <string>

#include "zeek/Desc.h"
#include "zeek/Val.h"
#include "zeek/ZVal.h"

namespace zeek::detail {

// Base class for tracking information about a single cat() argument, with
// optimizations for some common cases.
class CatArg {
public:
    CatArg(std::string _s) : s(std::move(_s)) { max_size = s->size(); }

    virtual ~CatArg() = default;

    size_t MaxSize(const ZVal& zv) { return max_size ? *max_size : ComputeMaxSize(zv); }

    virtual void RenderInto(const ZVal& zv, char*& res, char* res_end) {
        auto n = *max_size;
        memcpy(res, s->data(), n);
        res += n;
    }

protected:
    CatArg() = default;
    CatArg(size_t _max_size) : max_size(_max_size) {}

    virtual size_t ComputeMaxSize(const ZVal& zv) { return 0; }

    // Present if max size is known a priori.
    std::optional<size_t> max_size;

    // Present if the argument is a constant.
    std::optional<std::string> s;
};

class FixedCatArg : public CatArg {
public:
    FixedCatArg(TypePtr t);

    void RenderInto(const ZVal& zv, char*& res, char* res_end) override;

protected:
    TypePtr t;
};

class StringCatArg : public CatArg {
public:
    StringCatArg() : CatArg() {}

    void RenderInto(const ZVal& zv, char*& res, char* res_end) override {
        auto s = zv.AsString();
        auto n = s->Len();
        memcpy(res, s->Bytes(), n);
        res += n;
    }

protected:
    size_t ComputeMaxSize(const ZVal& zv) override { return zv.AsString()->Len(); }
};

class PatternCatArg : public CatArg {
public:
    PatternCatArg() : CatArg() {}

    void RenderInto(const ZVal& zv, char*& res, char* res_end) override {
        *(res++) = '/';
        strcpy(res, text);
        res += n;
        *(res++) = '/';
    }

protected:
    size_t ComputeMaxSize(const ZVal& zv) override;

    const char* text = nullptr;
    size_t n = 0;
};

class DescCatArg : public CatArg {
public:
    DescCatArg(TypePtr _t) : CatArg(), t(std::move(_t)) { d.SetStyle(RAW_STYLE); }

    void RenderInto(const ZVal& zv, char*& res, char* res_end) override {
        auto n = d.Size();
        memcpy(res, d.Bytes(), n);
        res += n;
        d.Clear();
    }

protected:
    size_t ComputeMaxSize(const ZVal& zv) override {
        zv.ToVal(t)->Describe(&d);
        return d.Size();
    }

    ODesc d;
    TypePtr t;
};

} // namespace zeek::detail
