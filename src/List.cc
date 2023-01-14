#include "zeek/List.h"

#include "zeek/3rdparty/doctest.h"

TEST_CASE("list construction")
	{
	zeek::List<int> list;
	CHECK(list.empty());

	zeek::List<int> list2(10);
	CHECK(list2.empty());
	CHECK(list2.max() == 10);
	}

TEST_CASE("list operation")
	{
	zeek::List<int> list({1, 2, 3});
	CHECK(list.size() == 3);
	CHECK(list.max() == 3);
	CHECK(list[0] == 1);
	CHECK(list[1] == 2);
	CHECK(list[2] == 3);

	// push_back forces a resize of the list here, which grows the list
	// by a growth factor. That makes the max elements equal to 6.
	list.push_back(4);
	CHECK(list.size() == 4);
	CHECK(list.max() == 6);
	CHECK(list[3] == 4);

	CHECK(list.front() == 1);
	CHECK(list.back() == 4);

	list.pop_front();
	CHECK(list.size() == 3);
	CHECK(list.front() == 2);

	list.pop_back();
	CHECK(list.size() == 2);
	CHECK(list.back() == 3);

	list.push_back(4);
	CHECK(list.is_member(2));
	CHECK(list.member_pos(2) == 0);

	list.remove(2);
	CHECK(list.size() == 2);
	CHECK(list[0] == 3);
	CHECK(list[1] == 4);

	// Squash the list down to the existing elements.
	list.resize();
	CHECK(list.size() == 2);
	CHECK(list.max() == 2);

	// Attempt replacing a known position.
	int old = list.replace(0, 10);
	CHECK(list.size() == 2);
	CHECK(list.max() == 2);
	CHECK(old == 3);
	CHECK(list[0] == 10);
	CHECK(list[1] == 4);

	// Attempt replacing an element off the end of the list, which
	// causes a resize.
	old = list.replace(3, 5);
	CHECK(list.size() == 4);
	CHECK(list.max() == 4);
	CHECK(old == 0);
	CHECK(list[0] == 10);
	CHECK(list[1] == 4);
	CHECK(list[2] == 0);
	CHECK(list[3] == 5);

	// Attempt replacing an element with a negative index, which returns the
	// default value for the list type.
	old = list.replace(-1, 50);
	CHECK(list.size() == 4);
	CHECK(list.max() == 4);
	CHECK(old == 0);

	list.clear();
	CHECK(list.size() == 0);
	CHECK(list.max() == 0);
	}

TEST_CASE("list iteration")
	{
	zeek::List<int> list({1, 2, 3, 4});

	int index = 1;
	for ( int v : list )
		CHECK(v == index++);

	index = 1;
	for ( auto it = list.begin(); it != list.end(); index++, ++it )
		CHECK(*it == index);
	}

TEST_CASE("plists")
	{
	zeek::PList<int> list;
	list.push_back(new int{1});
	list.push_back(new int{2});
	list.push_back(new int{3});

	CHECK(*list[0] == 1);

	int* new_val = new int(5);
	auto old = list.replace(-1, new_val);
	delete new_val;
	CHECK(old == nullptr);

	for ( auto v : list )
		delete v;
	list.clear();
	}

TEST_CASE("unordered list operation")
	{
	zeek::List<int, zeek::ListOrder::UNORDERED> list({1, 2, 3, 4});
	CHECK(list.size() == 4);

	// An unordered list doesn't maintain the ordering of the elements when
	// one is removed. It just swaps the last element into the hole.
	list.remove(2);
	CHECK(list.size() == 3);
	CHECK(list[0] == 1);
	CHECK(list[1] == 4);
	CHECK(list[2] == 3);
	}
