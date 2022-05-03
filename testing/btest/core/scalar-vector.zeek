# Skip this test when using ZAM, as it will generate a hard error in addition
# to the warning.
# @TEST-REQUIRES: test "${ZEEK_ZAM}" != "1"
#
# @TEST-EXEC: zeek -b %INPUT > out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER="$SCRIPTS/diff-remove-abspath" btest-diff out

event zeek_init()
      {
      const sv = vector("a", "b", "c");
      print sv == "b";
      print sv + "a";
      print "a" + sv;


      const nv = vector(1, 2, 3);
      print nv == 2;
      print nv * 2;
      print nv % 2;
      print nv / 2;

      const also_nv = nv += 1;
      print nv;
      }
