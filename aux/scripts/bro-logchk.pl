#!/usr/bin/perl

# Written by:
#     James J. Barlow <jbarlow@ncsa.uiuc.edu>
#     June 2002
#
# Orders and scans through bro http and ftp logs.

use Getopt::Std;
use Socket;

# Get the options on the command line
getopts('DFHdshra:f:x:');

# Check for invalid options or help option
if ($opt_h || ($opt_a && $opt_x) || (($opt_s || $opt_d) && !$opt_a) ||
   ($opt_F && $opt_H) || !($opt_F || $opt_H)) {
    &Usage;
}

# Read file
if ($opt_f) {
    open(INFILE, "$opt_f") || die "Can't open $opt_f: $!\n";
} else {
    &Usage;
}

$max = 0;

while (<INFILE>) {

    # is it the start of a connection
    if (check_start_conn()) {

        # Set to resolve IP address if $opt_r.
        $resolve = 1;

        # Do we want a specific IP address
        if ($opt_a) {
            if ((($source EQ $opt_a) && !$opt_d) || (($dest EQ $opt_a) && !$opt_s)) {
                # Yes, push connection number on list
                push @ipconlist, $conn;
            } else {
                $resolve = 0; # don't try to resolve IP address
            }
        }

        # Do we want to exclude an IP address
        if ($opt_x) {
            # Check if ipaddr is not excluded address
            if (($source NE $opt_x) && ($dest NE $opt_x)) {
                # if not push connection number on list
                push @ipconlist, $conn;
            } else {
                $resolve = 0; # don't try to resolve IP address
            }
        }

        # set max connection number
        $max = $conn if ($max < $conn);

        # Do we want to try and resolve IP addresses
        if ($opt_r && $resolve) {
            # get source and dest hostnames from IP addresses
            $sname = gethostbyaddr(inet_aton($source), AF_INET);
            # set source name to IP address if not resolvable
            if (!$sname) {
                $sname = $source;
            }
            $dname = gethostbyaddr(inet_aton($dest), AF_INET);
            # set destination name to IP address if not resolvable
            if (!$dname) {
                $dname = $dest;
            }
        } else {
            $sname = $source;
            $dname = $dest;
        }

        # Get timestamp
        $time = localtime($secs);

        # push connection 
        push @{$connlist[$conn]}, "$time - $conn  ${sname}${source_port} > $dname";
        print "$time - $conn  ${sname}${source_port} > $dname\n" if $opt_D;
        next;
    }

    # is it a request
    if (check_request()) {

        # set max connection number
        $max = $conn if ($max < $conn);

        push @{$connlist[$conn]}, "${time}${conn}  $request";
        print "${time}${conn}  $request\n" if $opt_D;
        next;
    }

    print "Unrecognized line: $_";
}

for ($i=1;$i<=$max;$i++) {
    # skip connections not on list if we want specific addrs
    # or are excluding addresses
    if ($opt_a || $opt_x) {
        next if !(grep /^$i$/, @ipconlist);
    }
    # print connections
    foreach $entry (@{$connlist[$i]}) {
        print "$entry\n";
    }
}

close(INFILE);


sub check_start_conn {

    $valid_conn = 0;

    # http connection?
    if ($opt_H) {
        if ((m/^(\d+)\s+%(\d+)\s+start\s+(\S+)\s+>\s+(\S+)/) ||
            (m/^(\d+)\.\d+\s+%(\d+)\s+start\s+(\S+)\s+>\s+(\S+)/)) {
            $secs = $1;
            $conn = $2;
            $source = $3;
            $dest = $4;
            chomp($dest);
            $source_port = "";
            $valid_conn = 1;
        }
    # ftp connection?
    } elsif ($opt_F) {
        if ((m/^(\d+)\s+#(\d+)\s+(\S+)\/(\d+)\s+>\s+(\S+)\/ftp start/) ||
            (m/^(\d+)\.\d+\s+#(\d+)\s+(\S+)\/(\d+)\s+>\s+(\S+)\/ftp start/)) {
            $secs = $1;
            $conn = $2;
            $source = $3;
            $source_port = "/$4";
            $dest = $5;
            $valid_conn = 1;
        }
    }

    return $valid_conn;
}

sub check_request {

    $valid_request = 0;

    if ($opt_H) {
        if (m/^%(\d+)\s+\S+\s+(.*)/) {
            $conn = $1;
            $request = "GET $2";
            chomp($request);
            $time = "";
            $valid_conn = 1;
        }
    } elsif ($opt_F) {
        if (m/^(\d+)\.\d+ #(\d+) (.*)/) {
            $time = localtime($1)." - ";
            $conn = $2;
            $request = $3;
            chomp($request);
            $valid_conn = 1;
        }
    }

    return $valid_conn;
}


#
# Usage
#
# Prints out usage for script.
             
sub Usage {
    print "Usage:\n";
    print "   bro-logchk.pl -[hrDFHds] -f filename -a ipaddr -x ipaddr\n";
    print "       -h          print this usage information\n";
    print "       -F          using ftp log\n";
    print "       -H          using http log\n";
    print "       -r          try to resolve IP addresses to hostnames\n";
    print "       -f file     log file to parse\n";
    print "       -a ipaddr   only output connections from this address\n";
    print "       -s          only want matching source address (used with -a option)\n";
    print "       -d          only want matching destination address (used with -a option)\n";
    print "       -D          debug option\n";
    print "       -x ipaddr   exclude connections from this address\n";
    print "\n";
    exit;
}

