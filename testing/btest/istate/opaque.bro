#
# @TEST-EXEC: bro -r $TRACES/empty.trace write.bro
# @TEST-EXEC: bro read.bro
# @TEST-EXEC: btest-diff expected.log
# @TEST-EXEC: btest-diff output.log
# @TEST-EXEC: cmp output.log expected.log

@TEST-START-FILE read.bro

global md5_handle: opaque of md5 &persistent &synchronized;
global sha1_handle: opaque of sha1 &persistent &synchronized;
global sha256_handle: opaque of sha256 &persistent &synchronized;
global entropy_handle: opaque of entropy &persistent &synchronized;

global bloomfilter_elements: set[string] &persistent &synchronized;
global bloomfilter_handle: opaque of bloomfilter &persistent &synchronized;

event bro_done()
  {
  local out = open("output.log");

  # Finish incremental operations started by a previous Bro.
  if ( md5_hash_update(md5_handle, "oo") )
    print out, md5_hash_finish(md5_handle);
  else
    print out, "md5_hash_update() failed";

  if ( sha1_hash_update(sha1_handle, "oo") )
    print out, sha1_hash_finish(sha1_handle);
  else
    print out, "sha1_hash_update() failed";

  if ( sha256_hash_update(sha256_handle, "oo") )
    print out, sha256_hash_finish(sha256_handle);
  else
    print out, "sha256_hash_update() failed";

  if ( entropy_test_add(entropy_handle, "oo") )
    print out, entropy_test_finish(entropy_handle);
  else
    print out, "entropy_test_add() failed";

  for ( e in bloomfilter_elements )
    print bloomfilter_lookup(bloomfilter_handle, e);
  }

@TEST-END-FILE

@TEST-START-FILE write.bro

global md5_handle: opaque of md5 &persistent &synchronized;
global sha1_handle: opaque of sha1 &persistent &synchronized;
global sha256_handle: opaque of sha256 &persistent &synchronized;
global entropy_handle: opaque of entropy &persistent &synchronized;

global bloomfilter_elements = { "foo", "bar", "baz" } &persistent &synchronized;
global bloomfilter_handle: opaque of bloomfilter &persistent &synchronized;

event bro_init()
  {
	local out = open("expected.log");
	print out, md5_hash("foo");
	print out, sha1_hash("foo");
	print out, sha256_hash("foo");
	print out, find_entropy("foo");

  # Begin incremental operations. Our goal is to feed the data string "foo" to
  # the computation, but split into "f" and "oo" in two instances..
  md5_handle = md5_hash_init();
  if ( ! md5_hash_update(md5_handle, "f") )
    print out, "md5_hash_update() failed";

  sha1_handle = sha1_hash_init();
  if ( ! sha1_hash_update(sha1_handle, "f") )
    print out, "sha1_hash_update() failed";

  sha256_handle = sha256_hash_init();
  if ( ! sha256_hash_update(sha256_handle, "f") )
    print out, "sha256_hash_update() failed";

  entropy_handle = entropy_test_init();
  if ( ! entropy_test_add(entropy_handle, "f") )
    print out, "entropy_test_add() failed";

  bloomfilter_handle = bloomfilter_basic_init(0.1, 100);
  for ( e in bloomfilter_elements )
    bloomfilter_add(bloomfilter_handle, e);
  }

@TEST-END-FILE
