package IP4;

use Exporter;
@ISA = ('Exporter');
@EXPORT = ( 'getIPFromString',
	    'getStringFromIP',
	    'getMaskFromPrefix',
	    'getPrefixFromMask',
	    'isPartOf',
	    'aggregateSinglesTo'
            );

use strict;
my $DEBUG = 0;

sub getIPFromString{
    my ($net) = @_;
    my @octets = split (/\./, $net);

    #check ip!
    foreach my $oct (@octets){
	if ($oct!~/\d+/ || $oct<0 || $oct > 255){return 0;}
    }

    my $ip=0;
    for (my $i = 0; $i < 4; $i++){
	$ip |= $octets[$i] << ((3-$i)*8);
    }
    return $ip;
}

sub getStringFromIP{
    my ($net) = @_;
    my @octets;
    my $bitmask=0xff;
    for (my $i = 0; $i<4; $i++){
	$octets[$i] = ($net & $bitmask);
	$net >>= 8;
    }
    return "$octets[3].$octets[2].$octets[1].$octets[0]";
}

sub getMaskFromPrefix{
    my ($pre) = @_;

    #check prefix!
    if ($pre!~/\d+/ || $pre < 0 || $pre > 32){return 0;}

    my $mask=0;
    for (my $i = 0; $i < $pre; $i++){
	$mask |= 1 << (31-$i);
    }
    return $mask;
}

sub getPrefixFromMask{
    my ($mask) = @_;
    if ($mask == 0){return 0}; #special case, we would loop forever with this:
    my $prefix;
    for ($prefix = 32; !($mask & 1); $prefix--){
	$mask >>= 1;
    }
    return $prefix;
}

sub isPartOf{
    my ($iip, $imask, $oip, $omask) = @_;
    if ($omask > $imask){return 0;} 
    #if the net which should contain the other is 
    #smaller we did something wrong!

    return ( (($oip ^ $iip) & $omask) == 0 );
} 

sub aggregateSinglesTo{
    #paramters: 
    #1. reference to array of addresses (will be changed!)
    #2. refernce to array of masks (will be deleted and changed)
    #3. max Bits to aggregate to.

    my ($addr, $masks, $bitlimit) = @_;
    $bitlimit = 32-$bitlimit; #the way it will be used we'll need the inverse 
    @$addr = sort{$a<=>$b}(@$addr) or return 0;
    @$masks = ();
    my $fullmask = getMaskFromPrefix(32);
    foreach my $dummy (@$addr){push(@$masks, $fullmask);}
    if ($DEBUG){
	print STDERR "sorted list before aggregating\n";
	print STDERR join(" ", map(getStringFromIP($_), @$addr));
	print STDERR "\n";
    }

	for (my $i = 0;
	     $i < (scalar(@$addr) - 1);
	     $i ++)
	{
	    my $lip = $addr->[$i];
	    my $lmask = $masks->[$i];
	    my $hip = $addr->[$i + 1];
	    my $hmask = $masks->[$i + 1];

	    if (isPartOf($hip, $hmask, $lip, $lmask)) { #parameter: (inner, outer)
		if ($DEBUG){
		    printf STDERR ("removing %s/%s since it is contained in %s/%s ", 
				   getStringFromIP($hip), getPrefixFromMask($hmask), 
				   getStringFromIP($lip), getPrefixFromMask($lmask) );
		}
		splice(@$addr, $i + 1, 1);
		splice(@$masks, $i + 1, 1);
		-- $i;
	    }else{
		my $nb = $lip;

		$nb ^= $hip; #look for first non-matching bit!
		my $firstdiff=0;
		while ($nb > 0){
		    $firstdiff++;
		    $nb >>= 1;
		}
		if ($firstdiff <= $bitlimit){
		    if ($DEBUG){print STDERR "$firstdiff : ";}
		    while($firstdiff>0){
			$firstdiff--;
			$nb <<= 1;
			$nb += 1;
		    }
		    
		    my $nm = ~$nb; #negate to get the new (joint) mask
		    my $na = $lip & $nm;
		    $addr->[$i] = $na;
		    $masks->[$i] = $nm;
		    if ($DEBUG){
			printf STDERR ("%s to %s/%s (aggregating %s)\n", 
				       getStringFromIP($lip), getStringFromIP($addr->[$i]), 
				       getPrefixFromMask($masks->[$i]), getStringFromIP($hip));
		    }
		    splice(@$addr, $i + 1, 1);
		    $i--; #do with the same address again. perhaps it collects even more
		}
	    }
	}
    if ($DEBUG){
	print STDERR "sorted list after aggregation\n";
	print STDERR join(" ", map(getStringFromIP($_), @$addr));
	print STDERR "\n";
    }
    return 1;
}

1;
