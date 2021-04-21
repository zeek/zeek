# @TEST-EXEC-FAIL: zeek -b %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr
# @TEST-DOC: Mismatched type-constructor initializations fail with reasonable error message

type R: record { a: bool &default=T; };
global t: table[string] of vector of string = vector();
global v0: vector of string = table();
global v1: vector of string = set();
global v2: vector of string = [];
global v3: vector of string = R();

local lt: table[string] of vector of string = vector();
local lv0: vector of string = table();
local lv1: vector of string = set();
local lv2: vector of string = [];
local lv3: vector of string = R();
