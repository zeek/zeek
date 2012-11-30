# This tests bro's mechanism to prevent duplicate script loading.
#
# @TEST-EXEC: mkdir -p foo/bar
# @TEST-EXEC: echo "@load bar/test" >loader.bro
# @TEST-EXEC: cp %INPUT foo/bar/test.bro
# @TEST-EXEC: BROPATH=$BROPATH:.:./foo bro -b misc/loaded-scripts loader bar/test
# @TEST-EXEC: BROPATH=$BROPATH:.:./foo bro -b misc/loaded-scripts loader bar/test.bro
# @TEST-EXEC: BROPATH=$BROPATH:.:./foo bro -b misc/loaded-scripts loader foo/bar/test
# @TEST-EXEC: BROPATH=$BROPATH:.:./foo bro -b misc/loaded-scripts loader foo/bar/test.bro
# @TEST-EXEC: BROPATH=$BROPATH:.:./foo bro -b misc/loaded-scripts loader `pwd`/foo/bar/test.bro

type Test: enum {
    TEST,
};
