// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <zeek/Type.h>
#include <cctype>

#include "zeek/ID.h"
#include "zeek/Val.h"
#include "zeek/util-types.h"

namespace zeek::benchmark {


inline RecordTypePtr get_string_string_args_type() {
    static zeek::RecordTypePtr rt;

    if ( rt )
        return rt;

    auto* tdl = new zeek::type_decl_list();
    auto* td1 = new zeek::TypeDecl("s1", zeek::base_type(zeek::TYPE_STRING));
    tdl->push_back(td1);
    auto* td2 = new zeek::TypeDecl("s2", zeek::base_type(zeek::TYPE_STRING));
    tdl->push_back(td2);


    rt = zeek::make_intrusive<zeek::RecordType>(tdl);
    zeek::Ref(rt.get());

    return rt;
}

/**
 * vector of count type
 */
inline zeek::VectorTypePtr get_vector_of_count_type() {
    static zeek::VectorTypePtr vt;

    if ( vt )
        return vt;
    vt = zeek::make_intrusive<zeek::VectorType>(zeek::base_type(zeek::TYPE_COUNT));

    return vt;
}

/**
 * A Broker Bin V1 of vector of count, vector(42, 4711).
 */
inline zeek::byte_buffer_span get_vector_of_count_example() {
    static const char buf[] = "\016\002\002\000\000\000\000\000\000\000*\002\000\000\000\000\000\000\022g";

    // Exclude \0 byte.
    return std::span{reinterpret_cast<const std::byte*>(buf), sizeof(buf) - 1};
}

/**
 * vector of string ytpe
 */
inline zeek::VectorTypePtr get_vector_of_string_type() {
    static zeek::VectorTypePtr vt;

    if ( vt )
        return vt;
    vt = zeek::make_intrusive<zeek::VectorType>(zeek::base_type(zeek::TYPE_STRING));

    return vt;
}

inline zeek::ValPtr get_vector_of_string_val() {
    auto vv = zeek::make_intrusive<zeek::VectorVal>(zeek::benchmark::get_vector_of_string_type());
    vv->Append(zeek::make_intrusive<zeek::StringVal>("forty-two"));
    vv->Append(zeek::make_intrusive<zeek::StringVal>("four-seven-eleven"));
    vv->Append(
        zeek::make_intrusive<zeek::StringVal>("a-really-long-string-just-so-that-we-test-the-var-encoding-a-bit-i-"
                                              "think-it-needs-to-be-really-long-longer-than-128-characters-at-least"));
    return vv;
}

/**
 * A Broker Bin V1 of vector of count, vector(42, 4711).
 */
inline zeek::byte_buffer_span get_vector_of_string_example() {
    static const char buf[] =
        "\016\003\005\011forty-two\005\021four-seven-eleven\005\207\001a-really-long-string-just-so-that-we-test-the-"
        "var-encoding-a-bit-i-think-it-needs-to-be-really-long-longer-than-128-characters-at-least";


    // Exclude \0 byte.
    return std::span{reinterpret_cast<const std::byte*>(buf), sizeof(buf) - 1};
}

/**
 * Create a record type
 *
 * type test_record_type: record {
 *   c1: count;   # 0
 *   s1: string   # 1
 *   t1: time     # 2
 *   i1: interval # 3
 *   v1: vector of count;  # 4
 * }
 */
inline zeek::RecordTypePtr get_test_record_type() {
    static zeek::RecordTypePtr rt;

    if ( rt )
        return rt;

    auto* tdl = new zeek::type_decl_list();

    auto* td1 = new zeek::TypeDecl("c1", zeek::base_type(zeek::TYPE_COUNT));
    tdl->push_back(td1);

    auto* td2 = new zeek::TypeDecl("s1", zeek::base_type(zeek::TYPE_STRING));
    tdl->push_back(td2);

    auto* td3 = new zeek::TypeDecl("t1", zeek::base_type(zeek::TYPE_TIME));
    tdl->push_back(td3);

    auto* td4 = new zeek::TypeDecl("i1", zeek::base_type(zeek::TYPE_INTERVAL));
    tdl->push_back(td4);

    auto* td5 = new zeek::TypeDecl("v1", get_vector_of_count_type());
    tdl->push_back(td5);

    rt = zeek::make_intrusive<zeek::RecordType>(tdl);
    zeek::Ref(rt.get());

    return rt;
};

/**
 * A Broker Bin V1 example of above record type.
 */
inline zeek::byte_buffer_span get_test_record_type_example() {
    static const char buf[] =
        "\016\005\002\000\000\000\000\000\000\000*\005'Forty\040Two\040is\040magic!\0404711\040is\040also\040funny."
        "\011\030\251\363\345\020s\317\000\012\000\000\000\011\307e$\000\016\002\002\000\000\000\000\000\000\000*"
        "\002\000\000\000\000\000\000\022g";

    // Exclude \0 byte.
    return std::span{reinterpret_cast<const std::byte*>(buf), sizeof(buf) - 1};
}

void inline dump_c_string(zeek::byte_buffer_span buf) {
    std::fprintf(stderr, "\n\n\"");
    for ( const auto b : buf ) {
        auto c = static_cast<unsigned int>(b);
        if ( c <= 0x20 || c >= 0x7f || std::isspace(c) ) {
            std::fprintf(stderr, "\\%03o", c);
        }
        else
            std::fprintf(stderr, "%c", c);
    }
    std::fprintf(stderr, "\"\n\n");
};


} // namespace zeek::benchmark
