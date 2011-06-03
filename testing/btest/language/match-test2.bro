# @TEST-EXEC: bro %INPUT  >output 2>&1
# @TEST-EXEC: btest-diff output

type fakealert : record {
     alert: string;
};


type match_rec : record {
     result : count;
     pred : function(rec : fakealert) : bool;
     priority: count;
};


#global test_set : set[int] = 
#{
#1, 2, 3
#};

global match_set : set[match_rec] = 
{
  [$result = 1, $pred(a: fakealert) = { return T; }, $priority = 8 ],
  [$result = 2, $pred(a: fakealert) = { return T; }, $priority = 9 ]
};

global al : fakealert;

#global testset : set[fakealert] = 
#{
#       [$alert="hithere"]
#};


type nonalert: record {
     alert : string;
     pred : function(a : int) : int;
};

#global na : nonalert;
#na$alert = "5";

#al$alert = "hithere2";
#if (al in testset)
#   print 1;
#else
#   print 0;


al$alert = "hi";
print (match al using match_set);
