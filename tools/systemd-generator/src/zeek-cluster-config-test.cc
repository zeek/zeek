// See the file "COPYING" in the main distribution directory for copyright.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"
#include "zeek-cluster-config.h"

TEST_SUITE("zeek-cluster-config helpers") {
    TEST_CASE("split") {
        using zeek::detail::split;
        using ssv = std::vector<std::string_view>;

        CHECK_EQ(split("", ','), ssv{""});
        CHECK_EQ(split(",", ','), ssv{"", ""});
        CHECK_EQ(split("1,", ','), ssv{"1", ""});
        CHECK_EQ(split("1,2", ','), ssv{"1", "2"});
        CHECK_EQ(split("9,10-12:1,18-24:2", ','), ssv{"9", "10-12:1", "18-24:2"});
        CHECK_EQ(split("9:10", ':'), ssv{"9", "10"});
        CHECK_EQ(split("9::10", ':'), ssv{"9", "", "10"});
    }

    TEST_CASE("substitute_vars") {
        using zeek::detail::substitute_vars;

        CHECK_EQ(substitute_vars("af_packet::eth0", {{"b", "XXX"}}), "af_packet::eth0");
        CHECK_EQ(substitute_vars("\\${a}", {{"a", "XXX"}}), "${a}");
        CHECK_EQ(substitute_vars("${a}", {{"a", "AAA"}}), "AAA");
        CHECK_EQ(substitute_vars("a\\${b}", {{"b", "XXX"}}), "a${b}");
        CHECK_EQ(substitute_vars("a\\${b}c", {{"b", "XXX"}}), "a${b}c");
        CHECK_EQ(substitute_vars("a\\${b}\\c", {{"b", "XXX"}}), "a${b}\\c");
        CHECK_EQ(substitute_vars("a${b}", {{"b", "BBB"}}), "aBBB");
        CHECK_EQ(substitute_vars("a${b}${c}", {{"b", "BBB"}, {"c", "CCC"}}), "aBBBCCC");
        CHECK_EQ(substitute_vars("a${b}x${c}y", {{"b", "BBB"}, {"c", "CCC"}}), "aBBBxCCCy");
    }

    TEST_CASE("cpu list parsing") {
        std::vector<std::string> invalid_cpu_lists = {
            "a",  ",",    "-",    ":",       "1,",      "1,,2",     ",2",      "-2",
            "2-", "2-3-", "1,2-", "3-2",     "1-2,3-2", "1-2:",     "1-2:0",   "1-2:-2",
            "1:", "1:0",  "1:1",  "1-2:1:2", "1-2:1:",  "1-2::1::", "1-2:1::",
        };

        for ( const auto& s : invalid_cpu_lists ) {
            SUBCASE((std::string("invalid ") + s).c_str()) {
                auto cpu_list = zeek::detail::CpuList(s);
                CHECK_FALSE(cpu_list.IsValid());
            }
        }

        SUBCASE("valid") {
            using iv = std::vector<int>;

            auto cl1 = zeek::detail::CpuList("");
            REQUIRE(cl1.IsValid());
            CHECK_EQ(cl1.Indices(), std::vector<int>{});

            auto cl2 = zeek::detail::CpuList("1");
            REQUIRE(cl2.IsValid());
            CHECK_EQ(cl2.Indices(), iv{1});

            auto cl3 = zeek::detail::CpuList("3,2,2,4");
            REQUIRE(cl3.IsValid());
            CHECK_EQ(cl3.Indices(), iv{{3, 2, 2, 4}});

            auto cl4 = zeek::detail::CpuList("1-4");
            REQUIRE(cl4.IsValid());
            CHECK_EQ(cl4.Indices(), iv{{1, 2, 3, 4}});

            auto cl5 = zeek::detail::CpuList("1,3-5");
            REQUIRE(cl5.IsValid());
            CHECK_EQ(cl5.Indices(), iv{{1, 3, 4, 5}});

            auto cl6 = zeek::detail::CpuList("1-5:2");
            REQUIRE(cl6.IsValid());
            CHECK_EQ(cl6.Indices(), iv{{1, 3, 5}});

            auto cl7 = zeek::detail::CpuList("9,10-12:1,18-24:2,19-22:3");
            REQUIRE(cl7.IsValid());
            CHECK_EQ(cl7.Indices(), iv{9, 10, 11, 12, 18, 20, 22, 24, 19, 22});

            auto cl8 = zeek::detail::CpuList("0-8:2,10-20:3");
            REQUIRE(cl8.IsValid());
            CHECK_EQ(cl8.Indices(), iv{0, 2, 4, 6, 8, 10, 13, 16, 19});
        }

        SUBCASE("indices set") {
            using iv = std::vector<int>;

            auto cl1 = zeek::detail::CpuList("0-3,0-3");
            REQUIRE(cl1.IsValid());
            CHECK_EQ(cl1.Indices(), iv{0, 1, 2, 3, 0, 1, 2, 3});
            CHECK_EQ(cl1.IndicesSetString(), "0,1,2,3");

            auto cl2 = zeek::detail::CpuList("3,2,1,0");
            REQUIRE(cl2.IsValid());
            CHECK_EQ(cl2.Indices(), iv{3, 2, 1, 0});
            CHECK_EQ(cl2.IndicesSetString(), "0,1,2,3");

            auto cl3 = zeek::detail::CpuList("3,2,1,0");
            REQUIRE(cl3.IsValid());
            CHECK_EQ(cl3.Indices(), iv{3, 2, 1, 0});
            CHECK_EQ(cl3.IndicesSetString(" "), "0 1 2 3");
        }
    }
}
