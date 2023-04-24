# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

function test_it(cid: conn_id, seed: count, expected: string)
	{
	local actual = community_id_v1(cid, seed);
	local prefix = actual == expected ? "PASS" : "FAIL";
	print fmt("%s: expected '%s', got '%s' (%s, seed=%d)", prefix, expected, actual, cid, seed);
	}

event zeek_init()
	{
	test_it([$orig_h=1.2.3.4, $orig_p=1122/tcp, $resp_h=5.6.7.8, $resp_p=3344/tcp], 0, "1:wCb3OG7yAFWelaUydu0D+125CLM=");
	test_it([$orig_h=1.2.3.4, $orig_p=1122/udp, $resp_h=5.6.7.8, $resp_p=3344/udp], 0, "1:0Mu9InQx6z4ZiCZM/7HXi2WMhOg=");
	test_it([$orig_h=1.2.3.4, $orig_p=8/icmp, $resp_h=5.6.7.8, $resp_p=0/icmp], 0, "1:crodRHL2FEsHjbv3UkRrfbs4bZ0=");
	test_it([$orig_h=[fe80:0001:0203:0405:0607:0809:0A0B:0C0D], $orig_p=128/icmp,
	         $resp_h=[fe80:1011:1213:1415:1617:1819:1A1B:1C1D], $resp_p=129/icmp], 0, "1:0bf7hyMJUwt3fMED7z8LIfRpBeo=");


	test_it([$orig_h=1.2.3.4, $orig_p=1122/tcp, $resp_h=5.6.7.8, $resp_p=3344/tcp], 1, "1:HhA1B+6CoLbiKPEs5nhNYN4XWfk=");
	test_it([$orig_h=1.2.3.4, $orig_p=1122/udp, $resp_h=5.6.7.8, $resp_p=3344/udp], 1, "1:OShq+iKDAMVouh/4bMxB9Sz4amw=");
	test_it([$orig_h=1.2.3.4, $orig_p=8/icmp, $resp_h=5.6.7.8, $resp_p=0/icmp], 1, "1:9pr4ZGTICiuZoIh90RRYE2RyXpU=");
	test_it([$orig_h=[fe80:0001:0203:0405:0607:0809:0A0B:0C0D], $orig_p=128/icmp,
	         $resp_h=[fe80:1011:1213:1415:1617:1819:1A1B:1C1D], $resp_p=129/icmp], 1, "1:IO27GQzPuCtNnwFvjWALMHu5tJE=");

	test_it([$orig_h=1.2.3.4, $orig_p=0/unknown, $resp_h=5.6.7.8, $resp_p=0/unknown], 0, "");
	test_it([$orig_h=[fe80:0001:0203:0405:0607:0809:0A0B:0C0D], $orig_p=0/unknown,
	         $resp_h=[fe80:1011:1213:1415:1617:1819:1A1B:1C1D], $resp_p=0/unknown], 1, "");
	}
