#
# Generate the yacc/bison grammar file parse.y from parse.in
#
# Importantly, it will eliminate the dependence on the internal location stack
# if it is not supported.
#

use strict;


# figure out which yacc-like thing is used
# ### Kind of a hack since it uses the Makefile

my $srcdir = $ARGV[0];
my $builddir = $ARGV[1];
my $yacc = $ARGV[2];

my $is_bison = ($yacc =~ /bison/);

if ($is_bison)
  {
    system ("cp $srcdir/parse.in $builddir/parse.y") == 0 or die "Could not make parse.y: $!\n";
  }
else
  {
    make_parser();
  }


sub make_parser
{
  open PARSE_OUT, ">$builddir/parse.y" or die "Could not open $builddir/parse.y: $!";
  open PARSE_IN, "$srcdir/parse.in" or die "Could not open $srcdir/parse.in: $!";

  while (<PARSE_IN>)
    {
      $_ =~ s/\@\d+/GetCurrentLocation\(\)/g;
      print PARSE_OUT $_;
    }

  # yylloc needs to be non-extern for non-bison systems, so stick it here
  print PARSE_OUT "\n/* Non-extern yylloc needed for non-bison system */\n",
    "YYLTYPE yylloc;\n"
}
