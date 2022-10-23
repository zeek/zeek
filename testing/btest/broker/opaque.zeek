# @TEST-GROUP: broker
#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

event zeek_init()
	{
	print "============ Topk";
	local k1: opaque of topk = topk_init(4);
	topk_add(k1, "a");
	topk_add(k1, "b");
	topk_add(k1, "b");
	topk_add(k1, "c");
	local k2 = Broker::__opaque_clone_through_serialization(k1);
	print type_name(k2);
	print topk_get_top(k1, 5);
	topk_add(k1, "shoulnotshowup");
	print topk_get_top(k2, 5);

	print "============ HLL";
	local c1 = hll_cardinality_init(0.01, 0.95);
	hll_cardinality_add(c1, 2001);
	hll_cardinality_add(c1, 2002);
	hll_cardinality_add(c1, 2003);

	print hll_cardinality_estimate(c1);
	local c2 = Broker::__opaque_clone_through_serialization(c1);
	print type_name(c2);
	hll_cardinality_add(c1, 2004);
	print hll_cardinality_estimate(c2);

	local c3 = hll_cardinality_init(0.01, 0.95);
	hll_cardinality_merge_into(c3, c2);
	print hll_cardinality_estimate(c3);

	print "============ Bloom";
	local bf_cnt = bloomfilter_basic_init(0.1, 1000);
	bloomfilter_add(bf_cnt, 42);
	bloomfilter_add(bf_cnt, 84);
	bloomfilter_add(bf_cnt, 168);
	print bloomfilter_lookup(bf_cnt, 0);
	print bloomfilter_lookup(bf_cnt, 42);
	local bf_copy = Broker::__opaque_clone_through_serialization(bf_cnt);
	print type_name(bf_copy);
	bloomfilter_add(bf_cnt, 0);
	print bloomfilter_lookup(bf_copy, 0);
	print bloomfilter_lookup(bf_copy, 42);
	# check that typefication transferred.
	bloomfilter_add(bf_copy, 0.5); # causes stderr output "error: incompatible Bloom filter types"

	print "============ Hashes";
	local md5a = md5_hash_init();
	md5_hash_update(md5a, "one");
	local md5b = Broker::__opaque_clone_through_serialization(md5a);
	print type_name(md5b);
	md5_hash_update(md5a, "two");
	md5_hash_update(md5b, "two");
	print md5_hash_finish(md5a);
	print md5_hash_finish(md5b);

	local sha1a = sha1_hash_init();
	sha1_hash_update(sha1a, "one");
	local sha1b = Broker::__opaque_clone_through_serialization(sha1a);
	print type_name(sha1b);
	sha1_hash_update(sha1a, "two");
	sha1_hash_update(sha1b, "two");
	print sha1_hash_finish(sha1a);
	print sha1_hash_finish(sha1b);

	local sha256a = sha256_hash_init();
	sha256_hash_update(sha256a, "one");
	local sha256b = Broker::__opaque_clone_through_serialization(sha256a);
	print type_name(sha256b);
	sha256_hash_update(sha256a, "two");
	sha256_hash_update(sha256b, "two");
	print sha256_hash_finish(sha256a);
	print sha256_hash_finish(sha256b);

	print "============ X509";
	local x509 = x509_from_der("\x30\x82\x03\x75\x30\x82\x02\x5D\xA0\x03\x02\x01\x02\x02\x0B\x04\x00\x00\x00\x00\x01\x15\x4B\x5A\xC3\x94\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x05\x05\x00\x30\x57\x31\x0B\x30\x09\x06\x03\x55\x04\x06\x13\x02\x42\x45\x31\x19\x30\x17\x06\x03\x55\x04\x0A\x13\x10\x47\x6C\x6F\x62\x61\x6C\x53\x69\x67\x6E\x20\x6E\x76\x2D\x73\x61\x31\x10\x30\x0E\x06\x03\x55\x04\x0B\x13\x07\x52\x6F\x6F\x74\x20\x43\x41\x31\x1B\x30\x19\x06\x03\x55\x04\x03\x13\x12\x47\x6C\x6F\x62\x61\x6C\x53\x69\x67\x6E\x20\x52\x6F\x6F\x74\x20\x43\x41\x30\x1E\x17\x0D\x39\x38\x30\x39\x30\x31\x31\x32\x30\x30\x30\x30\x5A\x17\x0D\x32\x38\x30\x31\x32\x38\x31\x32\x30\x30\x30\x30\x5A\x30\x57\x31\x0B\x30\x09\x06\x03\x55\x04\x06\x13\x02\x42\x45\x31\x19\x30\x17\x06\x03\x55\x04\x0A\x13\x10\x47\x6C\x6F\x62\x61\x6C\x53\x69\x67\x6E\x20\x6E\x76\x2D\x73\x61\x31\x10\x30\x0E\x06\x03\x55\x04\x0B\x13\x07\x52\x6F\x6F\x74\x20\x43\x41\x31\x1B\x30\x19\x06\x03\x55\x04\x03\x13\x12\x47\x6C\x6F\x62\x61\x6C\x53\x69\x67\x6E\x20\x52\x6F\x6F\x74\x20\x43\x41\x30\x82\x01\x22\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05\x00\x03\x82\x01\x0F\x00\x30\x82\x01\x0A\x02\x82\x01\x01\x00\xDA\x0E\xE6\x99\x8D\xCE\xA3\xE3\x4F\x8A\x7E\xFB\xF1\x8B\x83\x25\x6B\xEA\x48\x1F\xF1\x2A\xB0\xB9\x95\x11\x04\xBD\xF0\x63\xD1\xE2\x67\x66\xCF\x1C\xDD\xCF\x1B\x48\x2B\xEE\x8D\x89\x8E\x9A\xAF\x29\x80\x65\xAB\xE9\xC7\x2D\x12\xCB\xAB\x1C\x4C\x70\x07\xA1\x3D\x0A\x30\xCD\x15\x8D\x4F\xF8\xDD\xD4\x8C\x50\x15\x1C\xEF\x50\xEE\xC4\x2E\xF7\xFC\xE9\x52\xF2\x91\x7D\xE0\x6D\xD5\x35\x30\x8E\x5E\x43\x73\xF2\x41\xE9\xD5\x6A\xE3\xB2\x89\x3A\x56\x39\x38\x6F\x06\x3C\x88\x69\x5B\x2A\x4D\xC5\xA7\x54\xB8\x6C\x89\xCC\x9B\xF9\x3C\xCA\xE5\xFD\x89\xF5\x12\x3C\x92\x78\x96\xD6\xDC\x74\x6E\x93\x44\x61\xD1\x8D\xC7\x46\xB2\x75\x0E\x86\xE8\x19\x8A\xD5\x6D\x6C\xD5\x78\x16\x95\xA2\xE9\xC8\x0A\x38\xEB\xF2\x24\x13\x4F\x73\x54\x93\x13\x85\x3A\x1B\xBC\x1E\x34\xB5\x8B\x05\x8C\xB9\x77\x8B\xB1\xDB\x1F\x20\x91\xAB\x09\x53\x6E\x90\xCE\x7B\x37\x74\xB9\x70\x47\x91\x22\x51\x63\x16\x79\xAE\xB1\xAE\x41\x26\x08\xC8\x19\x2B\xD1\x46\xAA\x48\xD6\x64\x2A\xD7\x83\x34\xFF\x2C\x2A\xC1\x6C\x19\x43\x4A\x07\x85\xE7\xD3\x7C\xF6\x21\x68\xEF\xEA\xF2\x52\x9F\x7F\x93\x90\xCF\x02\x03\x01\x00\x01\xA3\x42\x30\x40\x30\x0E\x06\x03\x55\x1D\x0F\x01\x01\xFF\x04\x04\x03\x02\x01\x06\x30\x0F\x06\x03\x55\x1D\x13\x01\x01\xFF\x04\x05\x30\x03\x01\x01\xFF\x30\x1D\x06\x03\x55\x1D\x0E\x04\x16\x04\x14\x60\x7B\x66\x1A\x45\x0D\x97\xCA\x89\x50\x2F\x7D\x04\xCD\x34\xA8\xFF\xFC\xFD\x4B\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x05\x05\x00\x03\x82\x01\x01\x00\xD6\x73\xE7\x7C\x4F\x76\xD0\x8D\xBF\xEC\xBA\xA2\xBE\x34\xC5\x28\x32\xB5\x7C\xFC\x6C\x9C\x2C\x2B\xBD\x09\x9E\x53\xBF\x6B\x5E\xAA\x11\x48\xB6\xE5\x08\xA3\xB3\xCA\x3D\x61\x4D\xD3\x46\x09\xB3\x3E\xC3\xA0\xE3\x63\x55\x1B\xF2\xBA\xEF\xAD\x39\xE1\x43\xB9\x38\xA3\xE6\x2F\x8A\x26\x3B\xEF\xA0\x50\x56\xF9\xC6\x0A\xFD\x38\xCD\xC4\x0B\x70\x51\x94\x97\x98\x04\xDF\xC3\x5F\x94\xD5\x15\xC9\x14\x41\x9C\xC4\x5D\x75\x64\x15\x0D\xFF\x55\x30\xEC\x86\x8F\xFF\x0D\xEF\x2C\xB9\x63\x46\xF6\xAA\xFC\xDF\xBC\x69\xFD\x2E\x12\x48\x64\x9A\xE0\x95\xF0\xA6\xEF\x29\x8F\x01\xB1\x15\xB5\x0C\x1D\xA5\xFE\x69\x2C\x69\x24\x78\x1E\xB3\xA7\x1C\x71\x62\xEE\xCA\xC8\x97\xAC\x17\x5D\x8A\xC2\xF8\x47\x86\x6E\x2A\xC4\x56\x31\x95\xD0\x67\x89\x85\x2B\xF9\x6C\xA6\x5D\x46\x9D\x0C\xAA\x82\xE4\x99\x51\xDD\x70\xB7\xDB\x56\x3D\x61\xE4\x6A\xE1\x5C\xD6\xF6\xFE\x3D\xDE\x41\xCC\x07\xAE\x63\x52\xBF\x53\x53\xF4\x2B\xE9\xC7\xFD\xB6\xF7\x82\x5F\x85\xD2\x41\x18\xDB\x81\xB3\x04\x1C\xC5\x1F\xA4\x80\x6F\x15\x20\xC9\xDE\x0C\x88\x0A\x1D\xD6\x66\x55\xE2\xFC\x48\xC9\x29\x26\x69\xE0");
	local x5092 = Broker::__opaque_clone_through_serialization(x509);
	print type_name(x5092);
	print x509_parse(x509);
	print x509_parse(x5092);

	print "============ Entropy";
	local handle = entropy_test_init();
	entropy_test_add(handle, "dh3Hie02uh^s#Sdf9L3frd243h$d78r2G4cM6*Q05d(7rh46f!0|4-f");
	local handle2 = Broker::__opaque_clone_through_serialization(handle);
	print type_name(handle2);
	print entropy_test_finish(handle);
	print entropy_test_finish(handle2);

	print "============ broker::Data";
	local s1: Broker::Data = Broker::set_create();
	Broker::set_insert(s1, "hi");
	Broker::set_insert(s1, "there");
	local d2 = Broker::__opaque_clone_through_serialization(s1$data);
	print type_name(d2);
	print s1$data;
	print d2;
	print same_object(s1$data, d2) == F;

	print "============ broker::Set";
	local cs = Broker::set_create();
	Broker::set_insert(cs, "hi");
	Broker::set_insert(cs, "there");
	Broker::set_insert(cs, "!");

	local i = Broker::set_iterator(cs);
	while ( ! Broker::set_iterator_last(i) )
		{
		local ci = Broker::__opaque_clone_through_serialization(i);
		print fmt("| %s | %s | %s", Broker::set_iterator_value(i), Broker::set_iterator_value(ci), type_name(ci));
		Broker::set_iterator_next(i);
		Broker::set_iterator_next(ci);
		if ( ! Broker::set_iterator_last(i) )
			print fmt("  > %s | %s", Broker::set_iterator_value(i), Broker::set_iterator_value(ci));
		}

	print "============ broker::Table";
	local ct = Broker::table_create();
	Broker::table_insert(ct, "hi", 10);
	Broker::table_insert(ct, "there", 20);
	Broker::table_insert(ct, "!", 30);

	local j = Broker::table_iterator(ct);
	while ( ! Broker::table_iterator_last(j) )
		{
		local cj = Broker::__opaque_clone_through_serialization(j);
		print fmt("| %s | %s | %s", Broker::table_iterator_value(j), Broker::table_iterator_value(cj), type_name(cj));
		Broker::table_iterator_next(j);
		Broker::table_iterator_next(cj);
		if ( ! Broker::table_iterator_last(j) )
			print fmt("  > %s | %s", Broker::table_iterator_value(j), Broker::table_iterator_value(cj));
		}

	print "============ broker::Vector";
	local cv = Broker::vector_create();
	Broker::vector_insert(cv, 0, "hi");
	Broker::vector_insert(cv, 1, "there");
	Broker::vector_insert(cv, 2, "!");

	local k = Broker::vector_iterator(cv);
	while ( ! Broker::vector_iterator_last(k) )
		{
		local ck = Broker::__opaque_clone_through_serialization(k);
		print fmt("| %s | %s | %s", Broker::vector_iterator_value(k), Broker::vector_iterator_value(ck), type_name(ck));
		Broker::vector_iterator_next(k);
		Broker::vector_iterator_next(ck);
		if ( ! Broker::vector_iterator_last(k) )
			print fmt("  > %s | %s", Broker::vector_iterator_value(k), Broker::vector_iterator_value(ck));
		}

	print "============ broker::Record";
	local cr = Broker::record_create(3);
	Broker::record_assign(cr, 0, "hi");
	Broker::record_assign(cr, 1, "there");
	Broker::record_assign(cr, 2, "!");

	local l = Broker::record_iterator(cr);
	while ( ! Broker::record_iterator_last(l) )
		{
		local cl = Broker::__opaque_clone_through_serialization(l);
		print fmt("| %s | %s | %s", Broker::record_iterator_value(l), Broker::record_iterator_value(cl), type_name(cl));
		Broker::record_iterator_next(l);
		Broker::record_iterator_next(cl);
		if ( ! Broker::record_iterator_last(l) )
			print fmt("  > %s | %s", Broker::record_iterator_value(l), Broker::record_iterator_value(cl));
		}

	}
