# @TEST-EXEC: zeek -b %INPUT > output
# @TEST-EXEC: btest-diff output

@load base/utils/hash_hrw

local pool = HashHRW::Pool();
local alice =   HashHRW::Site($id=0, $user_data="alice");
local bob =     HashHRW::Site($id=1, $user_data="bob");
local charlie = HashHRW::Site($id=2, $user_data="charlie");
local dave =    HashHRW::Site($id=3, $user_data="dave");
local eve =     HashHRW::Site($id=4, $user_data="eve");

print HashHRW::add_site(pool, alice);
print HashHRW::add_site(pool, alice);
print HashHRW::add_site(pool, bob);
print HashHRW::add_site(pool, charlie);
print HashHRW::add_site(pool, dave);
print HashHRW::add_site(pool, eve);
print HashHRW::rem_site(pool, charlie);
print HashHRW::rem_site(pool, charlie);

print HashHRW::get_site(pool, "one");
print HashHRW::get_site(pool, "two");
print HashHRW::get_site(pool, "three");
print HashHRW::get_site(pool, "four");
print HashHRW::get_site(pool, "four");
print HashHRW::get_site(pool, "five");
print HashHRW::get_site(pool, "six");
print HashHRW::get_site(pool, 1);
print HashHRW::get_site(pool, 2);
print HashHRW::get_site(pool, 3);

print HashHRW::rem_site(pool, alice);

print HashHRW::get_site(pool, "one");
print HashHRW::get_site(pool, "two");
print HashHRW::get_site(pool, "three");
print HashHRW::get_site(pool, "four");
print HashHRW::get_site(pool, "four");
print HashHRW::get_site(pool, "five");
print HashHRW::get_site(pool, "six");
print HashHRW::get_site(pool, 1);
print HashHRW::get_site(pool, 2);
print HashHRW::get_site(pool, 3);

print HashHRW::add_site(pool, alice);

print HashHRW::get_site(pool, "one");
print HashHRW::get_site(pool, "two");
print HashHRW::get_site(pool, "three");
print HashHRW::get_site(pool, "four");
print HashHRW::get_site(pool, "four");
print HashHRW::get_site(pool, "five");
print HashHRW::get_site(pool, "six");
print HashHRW::get_site(pool, 1);
print HashHRW::get_site(pool, 2);
print HashHRW::get_site(pool, 3);
