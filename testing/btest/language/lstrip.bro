#
# @TEST-EXEC: bro -b %INPUT >out
# @TEST-EXEC: btest-diff out

event bro_init()
	{
  local link_test = "https://www.zeek.org";
  local one_side = "abcdcab";
  local nothing = "";
  local strange_chars = "ådog";

  print fmt("%s", lstrip(link_test, "htps:/"));
  print fmt("%s", lstrip(one_side,"abc"));
  print fmt("%s", lstrip("","å"));
  print fmt("%s", lstrip(link_test,""));
  print fmt("%s", lstrip(strange_chars,"å"));
	}
