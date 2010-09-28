package Bro::Log;

require 5.006_001;
use strict;
use Bro::Config( '$BRO_CONFIG' );
use Time::Local;

use vars qw( $VERSION
			$BROLOGS );

# $Id: Log.pm 2865 2006-04-27 19:09:18Z tierney $
$VERSION = 1.20;



# This is the bare minimum format in which the filename must conform
my $FILENAME_REGEX = qr/^[[:alnum:]]\.(?:log|[[:print:]]\.[[:print:]])/;

# filename produced by Bro running from a trace file
my $name_trace = qr/^([[:alnum:]]+)\.log$/;

# filename produced from a Bro running on live traffic and currently open
# or logs that are not rotated or post processed
my $name_running = qr/^([[:alnum:]]+)	# log name
				\.	# seperator
				([^-][[:alnum:]-]*(?:\.[^-][[:alnum:]-])*)	# hostname
				\.	# seperator
				([[:digit:]]{2}-[[:digit:]]{2}-[[:digit:]]{2} # date
				_	# time seperator
				[[:digit:]]{2}\.[[:digit:]]{2}\.[[:digit:]]{2})	# time
				$/x;

# filename produced after post processing for things like the GUI.  The 
# filename contains the log name, hostname, begin epoch time, and end 
# epoch time.
my $name_epoch_range = qr/^([[:alnum:]]+)	# log name
				\.	# seperator
				([^-][[:alnum:]-]*(?:\.[^-][[:alnum:]-])*)	# hostname
				\.	# seperator
				([[:digit:]]{10})	# beginning epoch time
				-	# seperator
				([[:digit:]]{10})	# ending epoch time
				$/x;

my $name_rotate_log = qr/^([[:alnum:]]+)   # log name
                 \.  # seperator
                   ([^-][[:alnum:]-]*(?:\.[^-][[:alnum:]-])*)  # hostname
                   \.	# seperator
                   ([[:digit:]]{2}-[[:digit:]]{2}-[[:digit:]]{2} # date
                   _	# time seperator
                   [[:digit:]]{2}\.[[:digit:]]{2}\.[[:digit:]]{2})	# time
                   -	# second time seperator
                   ([[:digit:]]{2}-[[:digit:]]{2}-[[:digit:]]{2} # date
                   _	# time seperator
                   [[:digit:]]{2}\.[[:digit:]]{2}\.[[:digit:]]{2})	# time
                   (\.log)?$/x;

sub activelog
{
	my $sub_name = 'activelog';

	my $log_dir = $BRO_CONFIG->{BROLOGS};
	my $ret_str;

	if( !( defined( $log_dir ) ) )
	{
		warn( "no log directory defined\n" );
		return( undef );
	}

	if( -f "$log_dir/active_log" )
	{
		if( open( I_FILE, "$log_dir/active_log" ) )
		{
			if( defined( $ret_str = <I_FILE> ) )
			{
				# remove any trailing newlines
				if( $ret_str !~ m/[[:space]]+$/ )
				{
					chomp( $ret_str );
				}
				else
				{
					return( 0 );
				}
			}
			else
			{
				return( 0 );
			}
		}
		else
		{
			warn( "Failed to read the active log file at $log_dir/active_log\n" );
		}

		close( I_FILE );
	}
	else
	{
		return( 0 );
	}

	return( $ret_str );
}

sub loglist
{
	my $sub_name = 'log_list';

	my $__log_type = $_[0] || return( undef );
	my $brologs_dir = $BRO_CONFIG->{BROLOGS};
	my @ret_list;

	if( opendir( DIR, $brologs_dir ) )
	{
		while( defined( my $file_name = readdir( DIR ) ) )
		{
			if( my $log_type = ( filenametoepochtime( $file_name ) )[0] )
			{
				if( $log_type eq $__log_type )
				{
					push( @ret_list, "$brologs_dir/$file_name" );
				}
			}
		}
	}
	else
	{
		warn( __PACKAGE__ . "::$sub_name, Unable to open the BROLOGS directory\n" );
		return( undef );
	}

	closedir( DIR );

	if( wantarray )
	{
		return( @ret_list );
	}
	else
	{
		return( \@ret_list );
	}
}

sub filenametoepochtime
{
	my $sub_name = 'filenametoepochtime';

	# returns the log name, hostname, start time, and end time
	# log name will always return.
	# If any of the other three are not available then return value
	# will be undef.
	
	my $filename = $_[0] || return( undef );
	my $log_name;
	my $host_name;
	my $start_time;
	my $end_time;
	
	if( ! $filename =~ $FILENAME_REGEX )
	{
		print "$filename is bad!!\n";
		return( undef );
	}
	
	# There are several ways in which the filename is formatted.  This
	# if tree attempts to parse each of those
	
	# Log name but no hostname or times.  This can occur when running Bro
	# from a trace file.
	if( $filename =~ $name_trace )
	{
		$log_name = $1;
	}
	# filename contains the log name, hostname, and start time.  This usually
	# occurs on filenames which are currently being written to or are not
	# rotated.
	elsif( my @file_parts = $filename =~ $name_running )
	{
		my $start_time_string;
		( $log_name, $host_name, $start_time_string ) = ( @file_parts );
		
		# split up the string so it can be passed to timetoepoch
		my @parts = $start_time_string =~ m/^([[:digit:]]{2})	# year
		-	# seperator
		([[:digit:]]{2})	# month
		-	# seperator
		([[:digit:]]{2}) # day
		_	# time seperator
		([[:digit:]]{2})	# hour
		\.	# seperator
		([[:digit:]]{2})	# minute
		\.	# seperator
		([[:digit:]]{2})	# second
		$/x;
		
		if( @parts == 6 )
		{
			$start_time = timetoepoch( @parts );
		}
		else
		{
			return( undef );
		}
	}
	# filename contains the log name, hostname, epoch start time, epoch end time
	elsif( my @file_parts = $filename =~ $name_epoch_range )
	{
		( $log_name, $host_name, $start_time, $end_time ) = @file_parts;
	}
    # filename contains the log name, hostname, start time and end time as
    # strings as put out by rotate logs.
    # i.e weird.lite3.06-04-27_10.40.53-06-04-27_10.41.12
    elsif( my @file_parts = $filename =~ $name_rotate_log )
    {
        my $start_time_string;
        my $end_time_string;

        ( $log_name, $host_name, $start_time_string, $end_time_string ) = @file_parts;

	#print "***** $filename: st: $start_time_string, et: $end_time_string\n";

        # look at the start date
        my @parts = $start_time_string =~ m/^([[:digit:]]{2})	# year
        -	# seperator
        ([[:digit:]]{2})	# month
        -	# seperator
        ([[:digit:]]{2}) # day
        _	# time seperator
        ([[:digit:]]{2})	# hour
        \.	# seperator
        ([[:digit:]]{2})	# minute
        \.	# seperator
        ([[:digit:]]{2})	# second
        $/x;
        $start_time = timetoepoch( @parts );

        # look at the start date
        @parts = $end_time_string =~ m/^([[:digit:]]{2})	# year
        -	# seperator
        ([[:digit:]]{2})	# month
        -	# seperator
        ([[:digit:]]{2}) # day
        _	# time seperator
        ([[:digit:]]{2})	# hour
        \.	# seperator
        ([[:digit:]]{2})	# minute
        \.	# seperator
        ([[:digit:]]{2})	# second
        $/x;

        $end_time = timetoepoch( @parts );

	#print "***** st: $start_time, et: $end_time\n";
    }
	else
	{
		return( undef );
	}
	
	return( $log_name, $host_name, $start_time, $end_time );
}

sub timetoepoch
{
	my $sub_name = 'timetoepoch';
	
	# arguments are in the order
	# year
	# month
	# day
	# hour
	# minutes
	# seconds
	
	my $epoch_time;
	my( $year, $mon, $day, $hour, $min, $sec ) = @_;
	# The month fed into timelocal is 0 based index
	if( $mon > 0 )
	{
		--$mon;
	}
	
	if( $epoch_time = timelocal($sec,$min,$hour,$day,$mon,$year) )
	{
		return( $epoch_time );
	}
	else
	{
		return( undef );
	}
}

1;
