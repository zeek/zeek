#include "zeek/DNS_Mapping.h"

#include <ares_nameser.h>

#include "zeek/3rdparty/doctest.h"
#include "zeek/DNS_Mgr.h"
#include "zeek/Reporter.h"

namespace zeek::detail
	{

DNS_Mapping::DNS_Mapping(std::string host, struct hostent* h, uint32_t ttl, int type)
	{
	Init(h);
	req_host = host;
	req_ttl = ttl;
	req_type = type;

	if ( names.empty() )
		names.push_back(std::move(host));
	}

DNS_Mapping::DNS_Mapping(const IPAddr& addr, struct hostent* h, uint32_t ttl)
	{
	Init(h);
	req_addr = addr;
	req_ttl = ttl;
	req_type = T_PTR;
	}

DNS_Mapping::DNS_Mapping(FILE* f)
	{
	Clear();
	init_failed = true;

	req_ttl = 0;
	creation_time = 0;

	char buf[512];

	if ( ! fgets(buf, sizeof(buf), f) )
		{
		no_mapping = true;
		return;
		}

	char req_buf[512 + 1], name_buf[512 + 1];
	int is_req_host;
	int failed_local;
	int num_addrs;

	if ( sscanf(buf, "%lf %d %512s %d %512s %d %d %" PRIu32, &creation_time, &is_req_host, req_buf,
	            &failed_local, name_buf, &req_type, &num_addrs, &req_ttl) != 8 )
		{
		no_mapping = true;
		return;
		}

	failed = static_cast<bool>(failed_local);

	if ( is_req_host )
		req_host = req_buf;
	else
		req_addr = IPAddr(req_buf);

	names.push_back(name_buf);

	for ( int i = 0; i < num_addrs; ++i )
		{
		if ( ! fgets(buf, sizeof(buf), f) )
			return;

		char* newline = strchr(buf, '\n');
		if ( newline )
			*newline = '\0';

		addrs.emplace_back(IPAddr(buf));
		}

	init_failed = false;
	}

ListValPtr DNS_Mapping::Addrs()
	{
	if ( failed )
		return nullptr;

	if ( ! addrs_val )
		{
		addrs_val = make_intrusive<ListVal>(TYPE_ADDR);

		for ( const auto& addr : addrs )
			addrs_val->Append(make_intrusive<AddrVal>(addr));
		}

	return addrs_val;
	}

TableValPtr DNS_Mapping::AddrsSet()
	{
	auto l = Addrs();

	if ( ! l || l->Length() == 0 )
		return DNS_Mgr::empty_addr_set();

	return l->ToSetVal();
	}

StringValPtr DNS_Mapping::Host()
	{
	if ( failed || names.empty() )
		return nullptr;

	if ( ! host_val )
		host_val = make_intrusive<StringVal>(names[0]);

	return host_val;
	}

void DNS_Mapping::Init(struct hostent* h)
	{
	no_mapping = false;
	init_failed = false;
	creation_time = util::current_time();
	host_val = nullptr;
	addrs_val = nullptr;

	if ( ! h )
		{
		Clear();
		return;
		}

	if ( h->h_name )
		// for now, just use the official name
		// TODO: this could easily be expanded to include all of the aliases as well
		names.push_back(h->h_name);

	if ( h->h_addr_list )
		{
		for ( int i = 0; h->h_addr_list[i] != NULL; ++i )
			{
			if ( h->h_addrtype == AF_INET )
				addrs.push_back(IPAddr(IPv4, (uint32_t*)h->h_addr_list[i], IPAddr::Network));
			else if ( h->h_addrtype == AF_INET6 )
				addrs.push_back(IPAddr(IPv6, (uint32_t*)h->h_addr_list[i], IPAddr::Network));
			}
		}

	failed = false;
	}

void DNS_Mapping::Clear()
	{
	names.clear();
	host_val = nullptr;
	addrs.clear();
	addrs_val = nullptr;
	no_mapping = false;
	req_type = 0;
	failed = true;
	}

void DNS_Mapping::Save(FILE* f) const
	{
	fprintf(f, "%.0f %d %s %d %s %d %zu %" PRIu32 "\n", creation_time, ! req_host.empty(),
	        req_host.empty() ? req_addr.AsString().c_str() : req_host.c_str(), failed,
	        names.empty() ? "*" : names[0].c_str(), req_type, addrs.size(), req_ttl);

	for ( const auto& addr : addrs )
		fprintf(f, "%s\n", addr.AsString().c_str());
	}

void DNS_Mapping::Merge(const DNS_MappingPtr& other)
	{
	std::copy(other->names.begin(), other->names.end(), std::back_inserter(names));
	std::copy(other->addrs.begin(), other->addrs.end(), std::back_inserter(addrs));
	}

// This value needs to be incremented if something changes in the data stored by Save(). This
// allows us to change the structure of the cache without breaking something in DNS_Mgr.
constexpr int FILE_VERSION = 1;

void DNS_Mapping::InitializeCache(FILE* f)
	{
	fprintf(f, "%d\n", FILE_VERSION);
	}

bool DNS_Mapping::ValidateCacheVersion(FILE* f)
	{
	char buf[512];
	if ( ! fgets(buf, sizeof(buf), f) )
		return false;

	int version;
	if ( sscanf(buf, "%d", &version) != 1 )
		{
		reporter->Warning("Existing DNS cache did not have correct version, ignoring");
		return false;
		}

	return FILE_VERSION == version;
	}

//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////

TEST_CASE("dns_mapping init null hostent")
	{
	DNS_Mapping mapping("www.apple.com", nullptr, 123, T_A);

	CHECK(! mapping.Valid());
	CHECK(mapping.Addrs() == nullptr);
	CHECK(mapping.AddrsSet()->EqualTo(DNS_Mgr::empty_addr_set()));
	CHECK(mapping.Host() == nullptr);
	}

TEST_CASE("dns_mapping init host")
	{
	IPAddr addr("1.2.3.4");
	in4_addr in4;
	addr.CopyIPv4(&in4);

	struct hostent he;
	he.h_name = util::copy_string("testing.home");
	he.h_aliases = NULL;
	he.h_addrtype = AF_INET;
	he.h_length = sizeof(in_addr);

	std::vector<in_addr*> addrs = {&in4, NULL};
	he.h_addr_list = reinterpret_cast<char**>(addrs.data());

	DNS_Mapping mapping("testing.home", &he, 123, T_A);
	CHECK(mapping.Valid());
	CHECK(mapping.ReqAddr() == IPAddr::v6_unspecified);
	CHECK(strcmp(mapping.ReqHost(), "testing.home") == 0);
	CHECK(mapping.ReqStr() == "testing.home");

	auto lva = mapping.Addrs();
	REQUIRE(lva != nullptr);
	CHECK(lva->Length() == 1);
	auto lvae = lva->Idx(0)->AsAddrVal();
	REQUIRE(lvae != nullptr);
	CHECK(lvae->Get().AsString() == "1.2.3.4");

	auto tvas = mapping.AddrsSet();
	REQUIRE(tvas != nullptr);
	CHECK_FALSE(tvas->EqualTo(DNS_Mgr::empty_addr_set()));

	auto svh = mapping.Host();
	REQUIRE(svh != nullptr);
	CHECK(svh->ToStdString() == "testing.home");

	delete[] he.h_name;
	}

TEST_CASE("dns_mapping init addr")
	{
	IPAddr addr("1.2.3.4");
	in4_addr in4;
	addr.CopyIPv4(&in4);

	struct hostent he;
	he.h_name = util::copy_string("testing.home");
	he.h_aliases = NULL;
	he.h_addrtype = AF_INET;
	he.h_length = sizeof(in_addr);

	std::vector<in_addr*> addrs = {&in4, NULL};
	he.h_addr_list = reinterpret_cast<char**>(addrs.data());

	DNS_Mapping mapping(addr, &he, 123);
	CHECK(mapping.Valid());
	CHECK(mapping.ReqAddr() == addr);
	CHECK(mapping.ReqHost() == nullptr);
	CHECK(mapping.ReqStr() == "1.2.3.4");

	auto lva = mapping.Addrs();
	REQUIRE(lva != nullptr);
	CHECK(lva->Length() == 1);
	auto lvae = lva->Idx(0)->AsAddrVal();
	REQUIRE(lvae != nullptr);
	CHECK(lvae->Get().AsString() == "1.2.3.4");

	auto tvas = mapping.AddrsSet();
	REQUIRE(tvas != nullptr);
	CHECK_FALSE(tvas->EqualTo(DNS_Mgr::empty_addr_set()));

	auto svh = mapping.Host();
	REQUIRE(svh != nullptr);
	CHECK(svh->ToStdString() == "testing.home");

	delete[] he.h_name;
	}

TEST_CASE("dns_mapping save reload")
	{
		// TODO: this test uses fmemopen and mkdtemp, both of which aren't available on
		// Windows. We'll have to figure out another way to do this test there.
#ifndef _MSC_VER
	IPAddr addr("1.2.3.4");
	in4_addr in4;
	addr.CopyIPv4(&in4);

	struct hostent he;
	he.h_name = util::copy_string("testing.home");
	he.h_aliases = NULL;
	he.h_addrtype = AF_INET;
	he.h_length = sizeof(in_addr);

	std::vector<in_addr*> addrs = {&in4, NULL};
	he.h_addr_list = reinterpret_cast<char**>(addrs.data());

	// Create a temporary file in memory and fseek to the end of it so we're at
	// EOF for the next bit.
	char buffer[4096];
	memset(buffer, 0, 4096);
	FILE* tmpfile = fmemopen(buffer, 4096, "r+");
	if ( fseek(tmpfile, 0, SEEK_END) < 0 )
		reporter->Error("DNS_Mapping: seek failed");

	// Try loading from the file at EOF. This should cause a mapping failure.
	DNS_Mapping mapping(tmpfile);
	CHECK(mapping.NoMapping());
	rewind(tmpfile);

	// Try reading from the empty file. This should cause an init failure.
	DNS_Mapping mapping2(tmpfile);
	CHECK(mapping2.InitFailed());
	rewind(tmpfile);

	// Save a valid mapping into the file and rewind to the start.
	DNS_Mapping mapping3(addr, &he, 123);
	mapping3.Save(tmpfile);
	rewind(tmpfile);

	// Test loading the mapping back out of the file
	DNS_Mapping mapping4(tmpfile);
	fclose(tmpfile);
	CHECK(mapping4.Valid());
	CHECK(mapping4.ReqAddr() == addr);
	CHECK(mapping4.ReqHost() == nullptr);
	CHECK(mapping4.ReqStr() == "1.2.3.4");

	auto lva = mapping4.Addrs();
	REQUIRE(lva != nullptr);
	CHECK(lva->Length() == 1);
	auto lvae = lva->Idx(0)->AsAddrVal();
	REQUIRE(lvae != nullptr);
	CHECK(lvae->Get().AsString() == "1.2.3.4");

	auto tvas = mapping4.AddrsSet();
	REQUIRE(tvas != nullptr);
	CHECK(tvas != DNS_Mgr::empty_addr_set());

	auto svh = mapping4.Host();
	REQUIRE(svh != nullptr);
	CHECK(svh->ToStdString() == "testing.home");

	delete[] he.h_name;
#endif
	}

TEST_CASE("dns_mapping multiple addresses")
	{
	IPAddr addr("1.2.3.4");
	in4_addr in4_1;
	addr.CopyIPv4(&in4_1);

	IPAddr addr2("5.6.7.8");
	in4_addr in4_2;
	addr2.CopyIPv4(&in4_2);

	struct hostent he;
	he.h_name = util::copy_string("testing.home");
	he.h_aliases = NULL;
	he.h_addrtype = AF_INET;
	he.h_length = sizeof(in_addr);

	std::vector<in_addr*> addrs = {&in4_1, &in4_2, NULL};
	he.h_addr_list = reinterpret_cast<char**>(addrs.data());

	DNS_Mapping mapping("testing.home", &he, 123, T_A);
	CHECK(mapping.Valid());

	auto lva = mapping.Addrs();
	REQUIRE(lva != nullptr);
	CHECK(lva->Length() == 2);

	auto lvae = lva->Idx(0)->AsAddrVal();
	REQUIRE(lvae != nullptr);
	CHECK(lvae->Get().AsString() == "1.2.3.4");

	lvae = lva->Idx(1)->AsAddrVal();
	REQUIRE(lvae != nullptr);
	CHECK(lvae->Get().AsString() == "5.6.7.8");

	delete[] he.h_name;
	}

TEST_CASE("dns_mapping ipv6")
	{
	IPAddr addr("64:ff9b:1::");
	in6_addr in6;
	addr.CopyIPv6(&in6);

	struct hostent he;
	he.h_name = util::copy_string("testing.home");
	he.h_aliases = NULL;
	he.h_addrtype = AF_INET6;
	he.h_length = sizeof(in6_addr);

	std::vector<in6_addr*> addrs = {&in6, NULL};
	he.h_addr_list = reinterpret_cast<char**>(addrs.data());

	DNS_Mapping mapping(addr, &he, 123);
	CHECK(mapping.Valid());
	CHECK(mapping.ReqAddr() == addr);
	CHECK(mapping.ReqHost() == nullptr);
	CHECK(mapping.ReqStr() == "64:ff9b:1::");

	auto lva = mapping.Addrs();
	REQUIRE(lva != nullptr);
	CHECK(lva->Length() == 1);
	auto lvae = lva->Idx(0)->AsAddrVal();
	REQUIRE(lvae != nullptr);
	CHECK(lvae->Get().AsString() == "64:ff9b:1::");

	delete[] he.h_name;
	}

	} // namespace zeek::detail
