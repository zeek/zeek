# Build the DebugCmdConstants.h and DebugCmdInfoConstants.h files from the
# DebugCmdInfoConstants.in file.
#
# We do this via a script rather than maintaining them directly because
# the struct is a little complicated, so has to be initialized from code,
# plus we want to make adding new constants somewhat less painful.
#
# The input filename should be supplied as an argument
#
# DebugCmds are printed to DebugCmdConstants.h
# DebugCmdInfos are printed to DebugCmdInfoConstants.h
#
# The input format is:
#
#	cmd: [DebugCmd]
#	names: [space delimited names of cmd]
#	resume: ['true' or 'false': should execution resume after this command?]
#	help: [some help text]
#
# Blank lines are skipped.
# Comments should start with // and should be on a line by themselves.

use strict;

open INPUT, $ARGV[0] or die "Input file $ARGV[0] not found.";
open DEBUGCMDS, ">DebugCmdConstants.h"
  or die "Unable to open DebugCmdConstants.h";
open DEBUGCMDINFOS, ">DebugCmdInfoConstants.cc"
  or die "Unable to open DebugCmdInfoConstants.cc";

my $init_tmpl =
'
   {
      DebugCmdInfo* info;
      @@name_init
      info = new DebugCmdInfo (@@cmd, names, @@num_names, @@resume, "@@help",
                               @@repeatable);
      g_DebugCmdInfos.push_back(info);
   }
';

my $enum_str = "
//
// This file was automatically generated from $ARGV[0]
// DO NOT EDIT.
//
enum DebugCmd {
";

my $init_str = "
//
// This file was automatically generated from $ARGV[0]
// DO NOT EDIT.
//

#include \"util.h\"
void init_global_dbg_constants () {
";

my %dbginfo;
# { cmd, num_names, \@names, name_init, resume, help, repeatable }

no strict "refs";
sub OutputRecord {
  $dbginfo{name_init} .= "const char * const names[] = {\n\t";
  $_ = "\"$_\"" foreach @{$dbginfo{names}};	# put quotes around the strings
  my $name_strs = join ",\n\t", @{$dbginfo{names}};
  $dbginfo{name_init} .= "$name_strs\n      };\n";

  $dbginfo{num_names} = scalar @{$dbginfo{names}};

  # substitute into template
  my $init = $init_tmpl;
  $init =~ s/(\@\@(\w+))/defined $dbginfo{$2} ? $dbginfo{$2} : ""/eg;

  $init_str .= $init;

  $enum_str .= "\t$dbginfo{cmd},\n";
}
use strict "refs";

sub InitDbginfo
  {
    my $dbginfo = shift;
    %$dbginfo = ( num_names => 0, names => [], resume => 'false', help => '',
		  repeatable => 'false' );
  }


InitDbginfo(\%dbginfo);

while (<INPUT>) {
  chomp ($_);
  next if $_ =~ /^\s*$/;	# skip blank
  next if $_ =~ /^\s*\/\//;	# skip comments

  $_ =~ /^\s*([a-z]+):\s*(.*)$/ or
    die "Error in debug constant file on line: $_";

  if ($1 eq 'cmd')
    {
      my $newcmd = $2;
      if (defined $dbginfo{cmd}) { # output the previous record	
	OutputRecord();
	InitDbginfo(\%dbginfo);
      }

      $dbginfo{cmd} = $newcmd;
    }
  elsif ($1 eq 'names')
    {
      my @names = split / /, $2;
      $dbginfo{names} = \@names;
    }
  elsif ($1 eq 'resume')
    {
      $dbginfo{resume} = $2;
    }
  elsif ($1 eq 'help')
    {
      $dbginfo{help} = $2;
      $dbginfo{help} =~ s{\"}{\\\"}g;	# escape quotation marks
    }
  elsif ($1 eq 'repeatable')
    {
      $dbginfo{repeatable} = $2;
    }
  else {
    die "Unknown command: $_\n";
  }
}

# output the last record
OutputRecord();

$init_str .= "   \n}\n";
$enum_str .= "   dcLast\n};\n";

print DEBUGCMDS $enum_str;
close DEBUGCMDS;

print DEBUGCMDINFOS $init_str;
close DEBUGCMDINFOS;
