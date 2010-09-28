#!/usr/bin/perl -w

# CVS/SVN wrapper script that maintains a nice ChangeLog for us.
# Heavily hacked & cleaned up, originally based upon a script
# that was once used in the Enlightenment project.

use strict;
use FileHandle;


# Prototypes
#_______________________________________________________________________

sub create_changelog;
sub validate_commit_message;
sub create_commit_message;
sub setup_username_translation;
sub update_changelog;
sub check_parameters;


# Globals
#_______________________________________________________________________
my %names;
my ($date, $author);

# Formats
#_______________________________________________________________________
format ENTRY =
@<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< @>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
$date, $author
.
    
    
# Subroutines
#_______________________________________________________________________
    
sub setup_username_translation {
    
    $names{"kreibich"} = "Christian <christian\@whoop.org>";
    $names{"cpk25"} = "Christian <christian\@whoop.org>";    
    $names{"christian"} = "Christian <christian\@whoop.org>";    
}



sub create_changelog {
    
    my $cl = "ChangeLog";
    my $num_lines;
    my $wc;
    my @lines;
    my @commitlines;
    my $line;
    
    print "Updating the ChangeLog with your entry.\n";
    
    if (open CHANGELOG, $cl) {
	@lines = <CHANGELOG>;
	close CHANGELOG;
	
	shift (@lines);
	shift (@lines);
    }  
    
    
    open CHANGELOG, ">$cl";
    print CHANGELOG <<eof;
Broccoli Changelog
========================================================================

eof

    if (open COMMITLOG, "CommitLog") {
	@commitlines = <COMMITLOG>;
	close COMMITLOG;
    }  
    
    CHANGELOG->format_name("ENTRY");
    $date   = `date`;
    $author = $names{$ENV{USER}};
    write CHANGELOG;
    CHANGELOG->format_name();
    print CHANGELOG "\n";
    print CHANGELOG @commitlines;
    print CHANGELOG "\n------------------------------------------------------------------------\n";
    print CHANGELOG @lines;
    close CHANGELOG;
}

sub create_commit_message {
    
    print "Please create a log message for the ChangeLog.\n";
    
    if (open COMMITLOG, ">CommitLog") {
	print COMMITLOG "-" x 72;
	print COMMITLOG "\n";
	close COMMITLOG;
    }  

    if($ENV{EDITOR}) {
	system("$ENV{EDITOR} CommitLog");
    } else {
	system("vi CommitLog");
    }
}


sub update_changelog {
  
    my @ARGV2;
    
    @ARGV2 = @ARGV;
    $ARGV2[0] = "update";
  
    print "Force updating ChangeLog\n";
    unlink "ChangeLog";
    system("svn update ChangeLog");
}


sub check_parameters {

    if (scalar(@ARGV) < 1) {
	print "USAGE: cvs.pl <comands> <files>\n";
	exit (0);
    }
}

# Main Program
#_______________________________________________________________________

check_parameters();
setup_username_translation();

if (($ARGV[0] =~ /com/) || ($ARGV[0] =~ /ci/)) {
    my @ARGV2;
    
    create_commit_message();
    update_changelog();
    
    $ARGV[0] .= " -F CommitLog";
    @ARGV2 = @ARGV;
    $ARGV2[0] = "update";
    
    print "Updating the files you are committing.\n";
    system("svn @ARGV2 2>&1 |tee errors");
    
    if (open ERRORS, "errors") {

	while(<ERRORS>) {

	    if (/conflicts during merge/) {
		print "There are one or more conflicts,\n" .
		      "Please resolve and try again.\n";
		unlink "errors" if(-f "errors");
		exit(0);
	    }
	}
	
	close ERRORS;
    }
    
    unlink "errors" if(-f "errors");    
    create_changelog();
    
    if($#ARGV >= 1) {

	my $found;
	
	$found = 0;

	foreach(@ARGV) {
	    $found = 1 if(/ChangeLog$/);
	}

	push @ARGV, "ChangeLog" if(! $found);
    }
}

print "svn @ARGV\n";
system("svn @ARGV");
print "Finished.\n"
