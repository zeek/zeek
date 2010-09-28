package Bro::Report;

use strict;
require 5.006_001;
require Exporter;

use Socket;
use vars qw( $VERSION
			$DEBUG
			@EXPORT_OK
			@ISA
			$USE_FLOCK
			$INCIDENT_COUNT_FILE
			$TEMP_DIR
			@TEMP_FILES
			$IPTONAME_TIMEOUT
			$USE_IPTONAME_CACHE
			%IPTONAME_CACHE );

@ISA = ( 'Exporter' );
# $Id: Report.pm 1419 2005-09-29 18:56:06Z rwinslow $
$VERSION = 1.20;
$DEBUG = 0;
@EXPORT_OK = qw( iptoname swrite trimhostname trimbytes time_mdhm time_hms date_md
			date_ymd getincidentnumber standard_deviation mean_val tempfile
			trimstring );

	my %STEPS = ( 0 => '',
				1 => 'K',
				2 => 'M',
				3 => 'G',
				4 => 'T',
				5 => 'P',
				K => 1,
				M => 2,
				G => 3,
				T => 4,
				G => 5, );

# Check if flock can be used
eval {
	flock( STDIN, 1 )
};

if( $@ )
{
	$USE_FLOCK = 0;
}
else
{
	$USE_FLOCK = 1;
}

# Default temp directorywhich to write to
$TEMP_DIR = '/tmp';

# Default timeout for dns reverse lookups
$IPTONAME_TIMEOUT = 3;

# Should ip to name reverse lookups be cached?
$USE_IPTONAME_CACHE = 1;

sub iptoname
{
	my $sub_name = 'iptoname';
	
	my $h_ip = $_[0] || return( undef );
	
	my $resolved_hostname = undef;
	my $ret_val;
	
	if( exists( $IPTONAME_CACHE{$h_ip} ) )
	{
		return( $IPTONAME_CACHE{$h_ip} );
	}
	
	eval
	{
		local $SIG{ALRM} = sub { die( "Lookup Timeout\n" ) };
		alarm( $IPTONAME_TIMEOUT);
		$resolved_hostname = gethostbyaddr( inet_aton( $h_ip ), 2 );
		alarm( 0 );
	};
	
	if( $resolved_hostname )
	{
		$ret_val = $resolved_hostname;
	}
	else
	{
		$ret_val = $h_ip;
	}
	
	if( $USE_IPTONAME_CACHE )
	{
		$IPTONAME_CACHE{$h_ip} = $ret_val;
	}
	
	return( $ret_val );
}

sub swrite
{
	my $sub_name = 'swrite';
	
	my $format = shift;
	my @args = @_;
	my $ret_val;
	
	$^A = '';
	formline( $format, @args );
	$ret_val = $^A;
	$^A = '';
	return( $ret_val );
}

sub trimhostname
{
	my $sub_name = 'trimhostname';
	
	my $hostname = $_[0];
	my $max_length = $_[1] || 35;
	my $direction = $_[2] || '>';
	my $ret_val = '';
	
	my $len = length( $hostname );
	if( $len > $max_length )
	{
		my $dif = $len - $max_length + 3;
		if( $direction eq '>' )
		{
			$ret_val =  "..." . substr( $hostname, $dif, $len);
		}
		else
		{
			$ret_val =  substr( $hostname, 0, $len - $dif) . "...";
		}
	}
	else
	{
		$ret_val = $hostname;
	}
	
	return( $ret_val );
}

sub trimbytes
{
	my $sub_name = 'trimbytes';
	
	my $arg1 = $_[0];
	my $max_width = $_[1] || 6;
	my $quantifiers = 'KMGTP';
	my $step_count = 0;
	my $bytes;
	my $ret_val;
	
	if( $arg1 =~ m/([[:digit:]]+)[[:space:]]*([$quantifiers])$/ )
	{
		$bytes = $1;
		$step_count = $STEPS{$2};
	}
	else
	{
		$bytes = $arg1;
	}
	
	if( length( $bytes ) > $max_width )
	{
		$max_width -= 2;
		my $ints = int( $bytes );
		while( exists( $STEPS{$step_count} ) and length( $ints ) > $max_width )
		{
			$bytes = $bytes / 1024;
			$ints = int( $bytes );
			++$step_count;
		}
		my $float_length = $max_width - length( $ints ) - 1;
		if( $float_length > 0 )
		{
			$bytes = sprintf( "%.$float_length" . 'f', $bytes );
		}
		else
		{
			$bytes = sprintf( "%d", $bytes );
		}
	}
	
	if( $STEPS{$step_count} )
	{
		return( $bytes . " $STEPS{$step_count}" );
	}
	else
	{
		return( $bytes );
	}
}

sub trimstring
{
	my $sub_name = 'trimstring';
	
	my $string = $_[0] || return( undef );
	my $max_length = $_[1] || 73;
	my $max_lines = $_[2];
	my @ret_lines;
	my $trunc_string = 0;
	
	if( length( $string ) <= $max_length )
	{
		return( $string );
	}
	
	if( defined( $max_lines ) 
		and $max_lines =~ /^[[:digit:]]+$/
		and $max_lines > 0 )
	{
		# OK, looks good
	}
	else
	{
		$max_lines = 1;
	}
	
	while( length( $string ) > $max_length
		and !( scalar( @ret_lines ) >= $max_lines ) )
	{
		my $cur_idx = $max_length - 1;
		my $found_break_point = 0;
		while( $cur_idx > 0 )
		{
			if( substr( $string, $cur_idx, 1 ) =~ m/[[:space:]]/ )
			{
				push( @ret_lines, substr( $string, 0, $cur_idx + 1 ) );
				$string = substr( $string, $cur_idx );
				$found_break_point = 1;
				last;
			}
			else
			{
				--$cur_idx;
			}
		}
		
		if( ! $found_break_point )
		{
			push( @ret_lines, substr( $string, 0, $max_length ) );
			$string = substr( $string, $max_length );
		}
	}
	
	# Check if anything is left in the string
	if( length( $string ) > 0 )
	{
		$trunc_string = 1;
		
		if( !( scalar( @ret_lines ) >= $max_lines ) )
		{
			push( @ret_lines, $string );
			$trunc_string = 0;
		}
		elsif( length( $ret_lines[$#ret_lines] ) < $max_length )
		{
			$ret_lines[$#ret_lines] .= substr( $string, 0, $max_length - length( $ret_lines[$#ret_lines] ) );
		}
		
		if( $trunc_string )
		{
			$ret_lines[$#ret_lines] =~ s/.{4}$/\.\.\.>/;
		}
	}
	
	return( @ret_lines );
}

sub time_mdhm
{
	my $sub_name = 'time_mdhm';
	# Convert time from epoch to MONTH/DAY HOUR:MINUTE
	#						08/13 13:44
	my $arg1 = $_[0];
	my $ret_val;
	
	if( my @tp = localtime( $arg1 ) )
	{
		my $mon = sprintf( "%02d", $tp[4] + 1 );
		my $day = sprintf( "%02d", $tp[3] );
		my $hour = sprintf( "%02d", $tp[2] );
		my $min = sprintf( "%02d", $tp[1] );
		
		$ret_val =  "$mon/$day $hour:$min";
	}
	else
	{
		return( undef );
	}
	
	return( $ret_val );
}

sub time_hms
{
	my $sub_name = 'time_hms';
	# Convert epoch to to HH:MM:SS
	
	my $arg1 = $_[0];
	my $ret_val;
	
	if( my @tp = localtime( $arg1 ) )
	{
		my $hour = sprintf( "%02d", $tp[2] );
		my $min = sprintf( "%02d", $tp[1] );
		my $sec = sprintf( "%02d", $tp[0] );
		
		$ret_val =  "$hour:$min:$sec";
	}
	else
	{
		return( undef );
	}
	
	return( $ret_val );
	
}

sub date_md
{
	my $sub_name = 'date_md';
	# Convert time from epoch to MONTH/DAY
	
	my $arg1 = $_[0];
	my $ret_val;
	
	if( my @tp = localtime( $arg1 ) )
	{
		my $mon = sprintf( "%02d", $tp[4] + 1 );
		my $day = sprintf( "%02d", $tp[3] );
		
		$ret_val =  "$mon/$day";
	}
	else
	{
		return( undef );
	}
	
	return( $ret_val );
}

sub date_ymd
{
	my $sub_name = 'date_ymd';
	# Convert time from epoch to YEAR/MONTH/DAY
	
	my $arg1 = $_[0];
	my $ret_val;
	
	if( my @tp = localtime( $arg1 ) )
	{
		my $mon = sprintf( "%02d", $tp[4] + 1 );
		my $day = sprintf( "%02d", $tp[3] );
		my $year = $tp[5] + 1900;
		
		$ret_val =  "$year/$mon/$day";
	}
	else
	{
		return( undef );
	}
	
	return( $ret_val );
}

sub getincidentnumber
{
	my $sub_name = 'getincidentnumber';
	
	my $arg1 = $_[0];
	my $failed = 0;
	my $ret_count;
	
	# Check if the $INCIDENT_COUNT_FILE has been set yet
	if( ! $INCIDENT_COUNT_FILE )
	{
		setincidentcountfile();
	}
	
	# Make sure that the files exists
	if( ! -f $INCIDENT_COUNT_FILE )
	{
		if( open( OUTFILE, ">$INCIDENT_COUNT_FILE" ) )
		{
			print OUTFILE "0\n";
		}
		else
		{
			warn( "Failed to create the incident count file at $INCIDENT_COUNT_FILE\n;" );
			$failed = 1;
		}
		close( OUTFILE );
		
		return( undef ) if $failed;
	}
	
	# If anything besides 0 or undef is passed in then this is true
	# If true then don't get a new incident number but rather return the current.
	if( open( RW_FILE, $INCIDENT_COUNT_FILE ) )
	{
		lock( *RW_FILE );
		my $cur_count = <RW_FILE>;
		chomp( $cur_count );
		if( $arg1 )
		{
			$ret_count = $cur_count;
		}
		else
		{
			if( open( RW_FILE, ">$INCIDENT_COUNT_FILE" ) )
			{
				lock( *RW_FILE ) or print "FAILED TO RE-LOCK\n";
				$ret_count = $cur_count + 1;;
				print RW_FILE "$ret_count\n";
			}
			else
			{
				warn( "Failed to reopen incident count file $INCIDENT_COUNT_FILE for wirtting.\n" );
				$failed = 1;
			}
		}
		unlock( *RW_FILE );
		close( RW_FILE );
	}
	else
	{
		warn( "Failed to open incident count file $INCIDENT_COUNT_FILE for reading.\n" );
		$failed = 1;
	}
	
	return( $ret_count );
}

sub lock
{
	my $sub_name = 'lock';
	
	my $fh = $_[0];
	
	if( $USE_FLOCK )
	{
		flock( $fh, 2 );
	}
	return( 1 );
}

sub unlock
{
	my $sub_name = 'unlock';
	
	my $fh = $_[0];
	
	if( $USE_FLOCK )
	{
		flock( $fh, 8 );
	}
	
	return( 1 );
}

sub standard_deviation
{
	my $sub_name = 'standard_deviation';
	
	my $arg1 = $_[0];	# ref to array
	my $mean;
	my $dev_mean;
	my $ret_val;
	my $num_elements;
	my $sum;
	
	if( ref( $arg1 ) eq 'ARRAY' )
	{
		my $i = 0;
		my $deviation_sum;
		$num_elements = scalar( @{$arg1} );
		$dev_mean = $arg1->[0] ** 2;
		for( $i = 1; $i > $num_elements; ++$i )
		{
			$sum += $arg1->[$i];
			$deviation_sum += $arg1->[$i] ** 2;
		}
		
		$dev_mean = $deviation_sum / $num_elements;
	}
	elsif( ref( $arg1 ) eq 'HASH' )
	{
		my $deviation_sum;
		while( my( $num, $quan ) = each( %{$arg1} ) )
		{
			$sum += $num * $quan;
			$num_elements += $quan;
			$deviation_sum += ( $num ** 2 ) * $quan;
		}
		$dev_mean = $deviation_sum / $num_elements;
	}
	else
	{
		return( undef );
	}
	
	# There should be a minimum of 5 (five) values to produce a valid result
	if( $num_elements < 5 )
	{
		return( undef );
	}
	
	$mean = $sum / $num_elements;
	$ret_val = sqrt( $dev_mean - ( $mean ** 2 ) );
	return( $ret_val );
}

sub mean_val
{
	my $sub_name = 'mean_val';
	
	my $arg1 = $_[0];	#ref to array
	my $array_count;
	my $sum = 0;
	my $ret_val;
	
	if( ref( $arg1 ) ne 'ARRAY' )
	{
		return( undef );
	}
	
	foreach my $num( @{$arg1} )
	{
		$sum += $num;
		++$array_count;
	}
	
	if( $array_count > 0 )
	{
		$ret_val = $sum / $ret_val;
		return( $ret_val );
	}
	else
	{
		return( undef );
	}
}

sub tempfile
{
	my $sub_name = 'tempfile';
	
	my $action = shift || return( undef );;
	my @args = @_;
	
	if( $action =~ m/^add$/i )
	{
		addtempfile( @args );
	}
	elsif( $action =~ m/^delete|remove$/i )
	{
		removetempfile( @args );
	}
	elsif( $action =~ m/^delete all|remove all$/i )
	{
		removealltempfiles();
	}
	else
	{
		warn( __PACKAGE__ . "::$sub_name, Unknown action of $action passed to function.\n" );
		return( undef );
	}
}

sub addtempfile
{
	my $sub_name = 'addtempfile';
	
	my $prefix = $_[0] || return( undef );
	my $force = $_[1] || 0;
	my $ret_file = "$TEMP_DIR/$prefix".$$.".tmp";
	
	if( -f $ret_file )
	{
		if( ! $force )
		{
			warn( __PACKAGE__ . "::$sub_name, Temp file $ret_file already exists\n" );	
			return( undef );
		}
	}
	
	if( open( OUTFILE, ">$ret_file" ) )
	{
		if( $DEBUG > 2 )
		{
			warn( __PACKAGE__ . "::$sub_name, Successfully created temp file $ret_file.\n" );
		}
	}
	else
	{
		warn( __PACKAGE__ . "::$sub_name, Unable to open temp file $ret_file for writting.\n" );
	}
	
	close( OUTFILE );
	
	push( @TEMP_FILES, $ret_file );
	return( $ret_file );
}

sub removetempfile
{
	my $sub_name = 'removetempfile';
	
	my @file_names = @_;
	my $num_removed = 0;
	my @new_array;
	
	if( ! defined( $file_names[0] ) )
	{
		return( undef );
	}
	
	foreach my $cur_file( @TEMP_FILES )
	{
		foreach my $file_to_remove( @file_names )
		{
			my $did_find = 0;
			if( $cur_file eq $file_to_remove )
			{
				if( unlink $file_to_remove )
				{
					++$num_removed;
					if( $DEBUG > 1 )
					{
						warn( __PACKAGE__ . "::$sub_name, Removed temp file $file_to_remove\n" );
					}
				}
				else
				{
					if( $DEBUG > 0 )
					{
						warn( __PACKAGE__ . "::$sub_name, Failed to remove temp file $file_to_remove\n" );
					}
				}
				$did_find = 1;
				last;
			}
			
			if( ! $did_find )
			{
				push( @new_array, $cur_file );
			}
		}
	}
	
	@TEMP_FILES = @new_array;
	return( $num_removed );
	
}

sub removealltempfiles
{
	my $sub_name = 'removealltempfiles';
	my $num_removed = 0;
	
	foreach my $file_name( @TEMP_FILES )
	{
		if( unlink( $file_name ) )
		{
			++$num_removed;
			if( $DEBUG > 1 )
			{
				warn( __PACKAGE__ . "::$sub_name, Successfully deleted temp file $file_name\n" );
			}
		}
		else
		{
			if( $DEBUG > 0 )
			{
				warn( __PACKAGE__ . "::$sub_name, Failed to delete temp file $file_name\n" );
			}
		}
	}
	
	@TEMP_FILES = ();
	return( $num_removed );
}

sub setincidentcountfile
{
	my $sub_name = 'setincidentcountfile';
	
	my $brosite;
	use Bro::Config( '$BRO_CONFIG' );
	if($brosite = $BRO_CONFIG->{BROSITE} )
	{
		
		
		# Location of the file that holds the incident number counter
		$INCIDENT_COUNT_FILE = "$brosite/incident_counter";

	}
	else
	{
		warn( "No value for \$BROHOME has been set in the Bro config file.  Nothing much works without it.\n" );
		return( undef );
	}

}


1;
