#!/usr/bin/perl

# look for our modules first
use lib '/usr/local/bro/perl/lib/perl5/site_perl';

# This is all stuff that needs to be set before compile time of other Bro modules
# because the other modules depend of Bro::Config to be configures properly
# given that the config file could be something different than the default.
BEGIN
{
	require 5.006_001;
	use vars qw( $VERSION
				$DEBUG
				$DEFAULT_CONFIG
				$RFC3339_REGEX
				$TEMP_DIR_NAME
				$DEFAULT_BRO_CONFIG_FILE
				$BRO_CONFIG_FILE );
	
	use Getopt::Long;
	Getopt::Long::Configure ( 'bundling', 'no_getopt_compat', 'pass_through', 'no_ignore_case' );
	use Bro::Config qw( $BRO_CONFIG );
	
	
	$DEFAULT_BRO_CONFIG_FILE = '/usr/local/bro/etc/bro.cfg';
	$BRO_CONFIG_FILE = getbroconfigfile() || $DEFAULT_BRO_CONFIG_FILE;
	Bro::Config::Configure( File => $BRO_CONFIG_FILE );
	
	sub getbroconfigfile
	{
		my $sub_name = 'getbroconfigfile';
		
		my %cmd_line_cfg;
		
		GetOptions( \%cmd_line_cfg,
				'broconfig|b=s' );
		
		return( $cmd_line_cfg{broconfig} );
	}
}


use strict;
use Time::Local;
use Socket;
			
# $Id: site-report.pl 5222 2008-01-09 20:05:27Z vern $
$VERSION = 1.06;
$TEMP_DIR_NAME = '.reports.tmp';

# A config file MUST exist in order to continue
if( $BRO_CONFIG->{BROHOME} )
{
	$DEFAULT_CONFIG = $BRO_CONFIG;
}
else
{
	print usage(), "\n";
	exit( 1 );
}

$DEFAULT_CONFIG->{'broconfig'} = $BRO_CONFIG_FILE;
$DEFAULT_CONFIG->{'report-range'} = 24;
$DEFAULT_CONFIG->{'report-start'} = 'yesterday';
$DEFAULT_CONFIG->{'max-hosts'} = 4000;
$DEFAULT_CONFIG->{'max-alarms'} = 300;
$DEFAULT_CONFIG->{'history-dir'} = $DEFAULT_CONFIG->{'BRO_HISTORY_DIR'};
$DEFAULT_CONFIG->{'report'} = $DEFAULT_CONFIG->{'BRO_REPORT_DIR'} . "/" . $DEFAULT_CONFIG->{'BRO_SITE_NAME'} . '.' . time() . ".$$.rpt";
$DEFAULT_CONFIG->{'temp'} = $DEFAULT_CONFIG->{'BROLOGS'};
$DEFAULT_CONFIG->{'summary_only'} = 1;
$DEFAULT_CONFIG->{'debug'} = 1;


$RFC3339_REGEX = qr/^([[:digit:]]{4})			# year
					-([[:digit:]]{2})		# month
					-([[:digit:]]{2})		# day
					(?:[Tt ]				# begin time section
					([[:digit:]]{2})		# hour
					(?::([[:digit:]]{2})	# minute
					(?::([[:digit:]]{2}(\.[[:digit:]]{1,2})?)|)|)	# second
					)?					# end time section
					([Zz]|([-+][[:digit:]]{2}:[[:digit:]]{2}))?	# timezone offset
					$/xo;

# sig handlers
$SIG{INT} = sub
{
	warn ("$0: caught INT signal.  Cleaning up...\n" );
	end_program();
	warn( "Done!\n" );
};

$SIG{TERM} = sub
{
	warn ("$0: caught TERM signal.  Cleaning up...\n" );
	end_program();
	warn( "Done!\n" );
};

$SIG{HUP} = 'IGNORE';

# hash ref that will contain all config data
my $config = {};

main();

sub main
{
	my $sub_name = 'main';
	
	$config = getconfig();
	
	# Must set/get the Bro config before loading some of these modules in the event that
	# a different bro.cfg file is specified.
	use Bro::Log;
	use Bro::Log::Conn;
	use Bro::Report qw( date_ymd time_hms );
	use Bro::Report::Conn;
	use Bro::Report::Alarm;
	use Bro::Log::Alarm;
	
	# Check if BRO_SITE_NAME has a value otherwise set a default
	if( length( $config->{BRO_SITE_NAME} ) < 1 )
	{
		$config->{BRO_SITE_NAME} = '_unknown_';
	}

	my @alarm_ordered_list;
	my @notice_ordered_list;
	my @conn_ordered_list;

	my $actual_stats;
	my $reported_stats;

	# Set the temp file directory
	$Bro::Report::TEMP_DIR = $config->{'temp'};

	# Get the list of alarm reports the user wants run.  Need to write this part
	my $alarm_report_input_funcs;
	my %alarm_report_output_funcs;
	$alarm_report_input_funcs = 'sub { my $alarm_struc = $_[0] || return( undef );'."\n";
	foreach my $report_name( Bro::Report::Alarm::availablereports() )
	{
		$alarm_report_output_funcs{$report_name} = Bro::Report::Alarm::reportoutputfunc( $report_name );
		if( my $input_func = Bro::Report::Alarm::reportinputfunc( $report_name ) )
		{
			$alarm_report_input_funcs .= $input_func . '( $alarm_struc );' . "\n";
		}
	}
	$alarm_report_input_funcs .= 'undef( $alarm_struc );' . "\n";
	$alarm_report_input_funcs .= '};'."\n";
	$alarm_report_input_funcs = eval $alarm_report_input_funcs;

	# Get the list of conn reports the user wants run.  Need to write this part
	my $conn_report_input_funcs;
	my %conn_report_output_funcs;
	$conn_report_input_funcs = 'sub { my $conn_struc = $_[0] || return( undef );'."\n";
	foreach my $report_name( Bro::Report::Conn::availablereports() )
	{
		$conn_report_output_funcs{$report_name} = Bro::Report::Conn::reportoutputfunc( $report_name );
		if( my $input_func = Bro::Report::Conn::reportinputfunc( $report_name ) )
		{
			$conn_report_input_funcs .= $input_func . '( $conn_struc );' . "\n";
		}
	}
	$conn_report_input_funcs .= 'undef( $conn_struc );' . "\n";
	$conn_report_input_funcs .= '};';
	$conn_report_input_funcs = eval $conn_report_input_funcs;

	# get a list of alarm files which contain data between the report start 
	# and end times
	# Sort ascending
	{
		if( $DEBUG > 2 )
		{
			warn( "Starting search for alarm files\n" );
		}

		my @file_list;
		foreach my $fn( Bro::Log::loglist( 'alarm' ) )
		{
			my( $start, $end ) = Bro::Log::Alarm::timerange( $fn );
			push( @file_list, [ $fn, $start, $end ] );

			if( $DEBUG > 3 )
			{
				print "Filename: $fn, Start: $start, End: $end\n";
			}
		}

		@alarm_ordered_list = filesinrange( \@file_list, 
									$config->{'report-start'},
									$config->{'report-end'} );
		if( $DEBUG > 2 )
		{
			warn( "List of alarm files which are within the time range -> " .
				join( ', ', @alarm_ordered_list ) . "\n" );
		}

		if( $DEBUG > 2 )
		{
			warn( "Finished search for alarm files\n" );
		}
	}

	# get a list of notice files which contain data between the report start 
	# and end times
	# Sort ascending
	{
		if( $DEBUG > 2 )
		{
			warn( "Starting search for notice files\n" );
		}

		my @file_list;
		foreach my $fn( Bro::Log::loglist( 'notice' ) )
		{
			my( $start, $end ) = Bro::Log::Alarm::timerange( $fn );
			push( @file_list, [ $fn, $start, $end ] );

			if( $DEBUG > 3 )
			{
				print "Filename: $fn, Start: $start, End: $end\n";
			}
		}

		@notice_ordered_list = filesinrange( \@file_list, 
									$config->{'report-start'},
									$config->{'report-end'} );
		if( $DEBUG > 2 )
		{
			warn( "List of notice files which are within the time range -> " .
				join( ', ', @notice_ordered_list ) . "\n" );
		}

		if( $DEBUG > 2 )
		{
			warn( "Finished search for notice files\n" );
		}
	}
	
	# get a list of conn files which contain data between the report start 
	# and end times
	# Sort ascending
	{
		if( $DEBUG > 2 )
		{
			warn( "Starting search for conn files\n" );
		}

		my @file_list;
		foreach my $fn( Bro::Log::loglist( 'conn' ) )
		{
			my( $start, $end ) = Bro::Log::Conn::timerange( $fn );

			if( defined( $start ) and defined( $end ) )
			{
				push( @file_list, [ $fn, $start, $end ] );
			}

			if( $DEBUG > 3 )
			{
				print "Filename: $fn, Start: $start, End: $end\n";
			}
		}


		@conn_ordered_list = filesinrange( \@file_list, 
									$config->{'report-start'},
									$config->{'report-end'} );

		if( $DEBUG > 2 )
		{
			warn( "List of connection files which are within the time range -> " .
				join( ', ', @conn_ordered_list ) . "\n" );
		}

		if( scalar( @conn_ordered_list ) < 1 )
		{
			warn( "No connection data found for the time period specified.\n" );
			warn( "Unable to create a report.\n" );
			exit ( 1 );
		}

		if( $DEBUG > 2 )
		{
			warn( "Finshed search for conn files\n" );
		}
	}

	my %interesting_addresses;
	if( @alarm_ordered_list )
	{
		if( $DEBUG > 2 )
		{
			warn( "Starting processing of alarm files\n" );
		}

		my $time_out_of_bounds = 0;
		my $last_timestamp = $config->{'report-start'};
		foreach my $al_fn( @alarm_ordered_list )
		{
			if( open( INFILE, $al_fn ) )
			{			
				while( defined( my $ln = <INFILE> ) )
				{
					my $alarm_struc = Bro::Log::Alarm::new( $ln );
					if( ! $alarm_struc )
					{
						next;
					}

					my $timestamp = Bro::Log::Alarm::timestamp( $alarm_struc );

					# Make sure that the file is at least up to the point of the
					# report-start time
					if( $timestamp < $config->{'report-start'} )
					{
						next;
					}

					if( $timestamp >= $last_timestamp and
						$timestamp <= $config->{'report-end'} )
					{
						$time_out_of_bounds = 0;

						&$alarm_report_input_funcs( $alarm_struc );

						if( my $src_ip = Bro::Log::Alarm::source_addr( $alarm_struc ) )
						{
							if( Bro::Report::Alarm::reportableoffense( $alarm_struc ) )
							{
								$interesting_addresses{$src_ip} = 1;
								if( $DEBUG > 3 )
								{
									my $offense = Bro::Log::Alarm::notice_type( $alarm_struc );
									warn( "Adding $src_ip to interesting list for $offense.\n" );
								}
							}
						}
						
						if( $time_out_of_bounds > 0 )
						{
							--$time_out_of_bounds;
						}
					}
					else
					{
						if( $time_out_of_bounds > 500 )
						{
							# Looks like we have reached a point beyond the
							# report-end time.
							if( $DEBUG > 3 )
							{
								warn( "Read over 500 lines which are beyond the end time of " .
									$config->{'report-end'} . ". Last read timestamp was $timestamp\n" );
							}
							last;
						}
						++$time_out_of_bounds;
						next;
					}
					$last_timestamp = $timestamp;
				}
			}
			else
			{

			}
			close( INFILE );
		}

		if( $DEBUG > 2 )
		{
			warn( "Finished processing alarm files\n" );
		}
	}

	foreach my $conn_file( @conn_ordered_list )
	{
		my $found_start = 0;
		my $found_end = 0;

		if( $DEBUG > 2 )
		{
			warn( "Starting processing of conn file $conn_file\n" );
		}

		# Create and open a temp file for incident conn data to be written to
		Bro::Report::Alarm::tempincidentfile();

		if( open( INFILE, $conn_file ) )
		{
			my $conn_struc;
			my $timestamp;
			my $duration;

			# This first loop is for checking if the beginning of the file has been
			# found.  Once found it will run the next loop.  Should save some time.
			while( ! $found_start and defined( my $line = <INFILE> ) )
			{
				my $within_range = 0;
				$conn_struc = Bro::Log::Conn::new( \$line ) or next;
				$timestamp = Bro::Log::Conn::timestamp( $conn_struc ) or next;
				$duration = Bro::Log::Conn::duration( $conn_struc );

				if( ( $timestamp >= $config->{'report-start'} or
					$timestamp + $duration >= $config->{'report-start'} ) and
					$timestamp <= $config->{'report-end'} )
				{
					$within_range = 1;
				}

				if( $within_range )
				{
					&$conn_report_input_funcs( $conn_struc );

					my $src_ip = Bro::Log::Conn::source_ip( $conn_struc );
					if( $interesting_addresses{$src_ip} )
					{
						Bro::Report::Alarm::addconndata( $conn_struc, \$line );
					}
					else
					{
						my $dest_ip = Bro::Log::Conn::destination_ip( $conn_struc );
						if( $interesting_addresses{$dest_ip} )
						{
							Bro::Report::Alarm::addconndata( $conn_struc, \$line );
						}
					}

					# Check to see if this is the logical place for connection data
					# within the time frame to begin.  Even though the start time
					# may not be greater than the start, anything from this point
					# forward will have be an active connection during the time range
					# given.
					if( $duration >= 0 and $duration < .01 )
					{
						$found_start = 1;
						last;
					}
				}
			}

			while( defined( my $line = <INFILE> ) )
			{
				$conn_struc = Bro::Log::Conn::new( \$line ) or next;
				$timestamp = Bro::Log::Conn::timestamp( $conn_struc ) or next;
				if( $timestamp <= $config->{'report-end'} )
				{
					&$conn_report_input_funcs( $conn_struc );

					my $src_ip = Bro::Log::Conn::source_ip( $conn_struc );
					if( $interesting_addresses{$src_ip} )
					{
						Bro::Report::Alarm::addconndata( $conn_struc, \$line );
					}
					else
					{
						my $dest_ip = Bro::Log::Conn::destination_ip( $conn_struc );
						if( $interesting_addresses{$dest_ip} )
						{
							Bro::Report::Alarm::addconndata( $conn_struc, \$line );
						}
					}
				}
			}
		}
		else
		{
			warn( "Failed to open conn file $conn_file for reading.\n" );
		}

		Bro::Report::Alarm::tempincidentfile( 'close' );
		close( INFILE );

		if( $DEBUG > 2 )
		{
			warn( "Finished processing conn file\n" );
		}
	}

	# Get the data now so the memory is released.
	my $conn_summ = output_connsummary();
    my $header;
    my $incident_summ;
    my $incident_details;
    my $system_summ;
    my $scan_summ;
    my $signature_distribution;

    if ($DEFAULT_CONFIG->{'summary_only'} == 0)
    {
	    # Gather up the different report pieces
	    $header = output_header();
	    $incident_summ = output_incidentsummary();
	    $incident_details = output_incidentdetails();
	    $system_summ = output_system_summary();
	    $scan_summ = output_scans();
	    $signature_distribution = output_signaturedistribution();
    }
	my $byte_transfer_pairs = output_bytetransferpairs();

	my $filename = $config->{'report'};
	print "Generating report file: " . $filename . "\n";
	if( open( OUTFILE, ">$filename" ) )
	{
        if ($DEFAULT_CONFIG->{'summary_only'} == 0)
        {
		    writereport( \*OUTFILE, $header, $conn_summ, $byte_transfer_pairs, );
        } else
        {
		    writereport( \*OUTFILE, $header, $incident_summ, 
					$incident_details, $signature_distribution, 
					$scan_summ, $conn_summ, $byte_transfer_pairs, );
        }
	}
	else
	{
		warn( "Failed to create report file at $filename\n" );
	}
	
	close( OUTFILE );

	end_program();

} # end main

#################################################
###                                           ###
###                 Begin Subs                ###
###                                           ###
#################################################


sub getconfig
{
	my $sub_name = 'getconfig';
	
	my $arg1 = shift || $DEFAULT_CONFIG;
	my %default_config;
	my %cmd_line_cfg;
	my %config;
	
	if( ref( $arg1 ) eq 'HASH' )
	{
		%default_config = %{$arg1};
	}
	else
	{
		return( undef );
	}
	
	GetOptions( \%cmd_line_cfg,
			'broconfig|b=s',
			'report-range|r=s',
			'report-start|s=s',
			'report-end|e=s',
			'max-hosts|i=s',
			'max-alarms|m=s',
			'history-dir=s',
			'temp|t=s',
			'usage|help|h',
			'debug|verbose|d|v:i',
			'summary_only|S',
			'version|V',
			'copyright', );
	
	# Check for options which will prevent the program from running
	# any further
	if( $cmd_line_cfg{usage} )
	{
		print usage();
		exit( 0 );
	}
	elsif( $cmd_line_cfg{version} )
	{
		print version();
		exit( 0 );
	}
	elsif( $cmd_line_cfg{copyright} )
	{
		print copyright();
		exit( 0 );
	}
	else
	{
		# just continue on
	}
	
	if( ! $cmd_line_cfg{brologs} )
	{
		$cmd_line_cfg{broconfig} = $default_config{broconfig};
	}
	
	# Any args passed through the command line will override file options
	while( my( $key, $value ) = each( %cmd_line_cfg ) )
	{
		$config{$key} = $value;
	}
	
	# Set default values for options that have not already been configured
	while( my( $key, $value ) = each( %{$arg1} ) )
	{
		if( ! exists( $config{$key} ) )
		{
			$config{$key} = $value;
		}
	}
	
	# Set Debug level
	$DEBUG = $config{debug} if exists( $config{debug} );
		
	if( checkconfig( \%config ) )
	{
		if( $DEBUG > 4 )
		{
			warn( "Configuration memory dump:\n" );
			warn( "\n" );
		}
		return( \%config );
	}
	else
	{
		warn( "exiting program\n" );
		exit( 1 );
	}
	
}

sub checkconfig
{
	my $sub_name = 'checkconfig';
	
	my $cfg_hash = shift || return undef;
	
	# Check to make sure that broconfig is defined.
	if( defined( $cfg_hash->{'broconfig'} ) )
	{
		# Check to make sure that the config filename has a sane value.
		if( $cfg_hash->{'broconfig'} !~ m/[*;`{}%]+/ and
				$cfg_hash->{'broconfig'} =~ m~^([[:print:]]{1,1024}?)/*$~ )
		{
			$cfg_hash->{'broconfig'} = $1;
			if( !( -f $cfg_hash->{'broconfig'} and -r $cfg_hash->{'broconfig'} ) )
			{
				warn( "broconfig file '" .$cfg_hash->{'broconfig'} . "' is not a file or can not be opened\n" );
				return( 0 );
			}
		}
		else
		{
			warn( "broconfig filename contains invalid characters or is longer than 1024 bytes\n" );
			return( 0 );
		}
	}
	else
	{
		warn( "No config file specified\n" );
		return( 0 );
	}
	
	# Check to make sure that start-time is at least one hour less than the current time
	if( defined( $cfg_hash->{'report-start'} ) )
	{
		# time() returns the gm time in epoch.  Add the timezone offset for calculation
		# purposes only.  The offset will later be subtracted before being set.
		my $_cur_time = time() + timezoneoffset();
		my $one_day = 24 * 60 * 60;
		
		if( $cfg_hash->{'report-start'} =~ m/yesterday/i )
		{
			my $_start_time = int( ( $_cur_time - $one_day ) / $one_day ) * $one_day;
			
			# Add some time to the start time.  This helps avoid the small overlap
			# encountered from a checkpoint and therefore less data to munge over.
			$_start_time = $_start_time + 30;
			$cfg_hash->{'report-start'} = $_start_time - timezoneoffset();
		}
		elsif( $cfg_hash->{'report-start'} =~ m/today/i )
		{
			my $_start_time = int( $_cur_time / $one_day ) * $one_day;
			$cfg_hash->{'report-start'} = $_start_time - timezoneoffset();
		}
		elsif( my $new_time = normalize_time( $cfg_hash->{'report-start'} ) )
		{
			$cfg_hash->{'report-start'} = $new_time;
		}
		else
		{
			warn( "report-start time '" . $cfg_hash->{'report-start'} . "' format is unknown.\n" );
			return( 0 );
		}
		
		if( $cfg_hash->{'report-start'} < ( time() - 3600 + 1 ) )
		{
			# ok
		}
		else
		{
			warn( "report-start must be at least one hour less than the current time.\n" );
			return( 0 );
		}
		
		if( $DEBUG > 2 )
		{
			warn( "report-start time: " . localtime($cfg_hash->{'report-start'}) .
				' (' . $cfg_hash->{'report-start'} . ')' . "\n" );
		}
	}
	else
	{
		warn( "report-start has not been defined\n" );
		return( 0 );
	}
	
	# Check to see if report-range was specified and report-end has not value
	if( defined( $cfg_hash->{'report-range'} ) and ! defined( $cfg_hash->{'report-end'} ) )
	{
		if( $cfg_hash->{'report-range'} =~ m/^[[:space:]]*((?:\+\-)?[[:digit:]]+)[[:space:]]*$/ )
		{
			$cfg_hash->{'report-range'} = $1;
			
			# report-range is given in hours, change to seconds
			my $_range = $cfg_hash->{'report-range'} * 60 * 60;
			$cfg_hash->{'report-end'} = $cfg_hash->{'report-start'} + $_range;
		}
		else
		{
			warn( "report-range argument '" . $cfg_hash->{'report-range'} . "' is unknown.\n" );
			return( 0 );
		}
		
		if( $cfg_hash->{'report-end'} < ( time() + 1 ) )
		{
			# ok
		}
		else
		{
			warn( "report-range + report-start exceeds the current time\n" );
			return( 0 );
		}
	}
	
	# Check to make sure that report-end is no greater than the current time
	if( defined( $cfg_hash->{'report-end'} ) )
	{
		if( ! ( $cfg_hash->{'report-end'} = int( normalize_time( $cfg_hash->{'report-end'} ) ) ) )
		{
			warn( "report-end time '" . $cfg_hash->{'report-end'} . "' format is unknown.\n" );
			return( 0 );
		}
		
		if( $cfg_hash->{'report-end'} < ( time() + 1 ) )
		{
			# ok
		}
		else
		{
			warn( "report-end must be equal to or less than the current time\n" );
			return( 0 );
		}
		
		if( $DEBUG > 2 )
		{
			warn( "report-end time: " . localtime($cfg_hash->{'report-end'}) .
				' (' . $cfg_hash->{'report-end'} . ')' . "\n" );
		}
	}
	else
	{
		warn( "report-end has not been defined\n" );
		return( 0 );
	}
	
	# Make sure that the report-end is at least one hour more than report-start
	if( ! ( ( $cfg_hash->{'report-end'} - 3600 ) >= $cfg_hash->{'report-start'} ) )
	{
		warn( "There must be at least one hour between the report-start and report-end times.\n" );
		return( 0 );
	}
	
	# Make sure that max-alarms is a number and greater than 0
	if( defined( $cfg_hash->{'max-alarms'} ) and 
		$cfg_hash->{'max-alarms'} =~ m/^[[:digit:]]+$/
		and $cfg_hash->{'max-alarms'} > 0 )
	{
		# ok
	}
	else
	{
		warn( "Invlaid value given for max-alarms.  Must be an number greater than 0\n" );
		return( 0 );
	}
	
	# Make sure that max-hosts is a number greater than 0
	if( defined( $cfg_hash->{'max-hosts'} ) and 
		$cfg_hash->{'max-hosts'} =~ m/^[[:digit:]]+$/
		and $cfg_hash->{'max-hosts'} > 0 )
	{
		# ok
	}
	else
	{
		warn( "Invalid value given for max-hosts.  Must be an number greater than 0\n" );
		return( 0 );
	}
	
	# Make sure the report file can be written to
	if( exists( $cfg_hash->{BRO_REPORT_DIR} ) )
	{
		if( ! -d $cfg_hash->{BRO_REPORT_DIR} )
		{
			if( $DEBUG > 0 )
			{
				warn( "\$BRO_REPORT_DIR " . $cfg_hash->{BRO_REPORT_DIR} . " is not a directory.\n" );
			}
		}
		elsif( ! -w $cfg_hash->{BRO_REPORT_DIR} )
		{
			warn( "\$BRO_REPORT_DIR " . $cfg_hash->{BRO_REPORT_DIR} . " is not writtable.\n" );
		}
	}
	else
	{
		if( $DEBUG > 0 )
		{
			warn( "\$BRO_REPORT_DIR environment variable has not been set.\n" );
		}
	}
	
	# Make sure that the temp directory is defined and writtable
	if( defined( $cfg_hash->{'temp'} ) )
	{
		my $full_path = $cfg_hash->{'temp'} . "/$TEMP_DIR_NAME";
		if( ! -d $cfg_hash->{'temp'} )
		{
			warn( "The temp directory at '" . $cfg_hash->{'temp'} . "' either does not exist or is not a directory.\n" );
			return( 0 );
		}
		
		if( ! -w $cfg_hash->{'temp'} )
		{
			warn( "The temp directory at '" . $cfg_hash->{'temp'} . "' is not writtable.\n" );
			return( 0 );
		}
		
		if( ! -d $full_path )
		{
			if( ! mkdir $full_path )
			{
				warn( "Unable to create the temp directory '$full_path' inside of '" . $cfg_hash->{'temp'} . "'.\n" );
				return( 0 );
			}
		}
		
		if( -w $full_path )
		{
			$cfg_hash->{'temp'} = $full_path;
		}
		else
		{
			warn( "Temp directory at '$full_path' is not writtable.\n" );
			return( 0 );
		}
	}
	else
	{
		warn( "No temp directory has been specified.\n" );
		return( 0 );
	}
	
	# Check for a history directory (not implemented yet)
	if( exists( $cfg_hash->{'history-dir'} ) and length( $cfg_hash->{'history-dir'} ) > 0 )
	{
		if( -d $cfg_hash->{'history-dir'} )
		{
			if( -r $cfg_hash->{'history-dir'} )
			{
				$cfg_hash->{'history-dir'} =~ m/^[[:space:]]*(.+?)[[:space:]]*$/;
				$cfg_hash->{'history-dir'} = $1;
			}
			else
			{
				if( $DEBUG > 0 )
				{
					warn( "Unable to read the history-dir at " . $cfg_hash->{'history-dir'} . "\n" );
				}
			}
		}
		else
		{
			if( $DEBUG > 1 )
			{
				warn( "The history directory at " . $cfg_hash->{'history-dir'} . " could not be found\n" );
			}
		}
	}
	
	return( 1 );
}

sub normalize_time
{
	my $sub_name = 'normalize_time';
	# change various time formats into a unix epoch time with 6 decimal places
	
	my $arg1 = $_[0];
	my $ret_time;
	
	if( $arg1 =~ m/^([[:digit:]]{10}(?:\.[[:digit:]]{1,6})?)$/ )
	{
		# Already in the right format.
		$ret_time = sprintf( "%.6f", $1 );
	}
	# ISO 8601 format -> 2004-08-06T19:59:39-0700
	elsif( my @time_parts = ( $arg1 =~ $RFC3339_REGEX ) )
	{
		my $year = $time_parts[0];
		my $mon = $time_parts[1];
		my $day = $time_parts[2];
		my $hour = $time_parts[3] || 0;
		my $min = $time_parts[4] || 0;
		my $sec = $time_parts[5] || 0;
		my $timezone = $time_parts[6] || undef;
		
		# month is zero based indexed
		if( $mon )
		{
			--$mon;
		}
		
		$ret_time = timelocal($sec,$min,$hour,$day,$mon,$year);
	}
	else
	{
		if( $DEBUG > 0 )
		{
			warn( "Unknown date format passed to sub $sub_name. Unable to convert time to a unix epoch time\n" );
		}
	}
	
	return( $ret_time );
}

sub filesinrange
{
	my $sub_name = 'filesinrange';
	
	my $_file_list = $_[0] || return( undef );
	my $_start = $_[1] || return( undef );
	my $_end = $_[2] || return( undef );
	my @ordered_list;
	my $found_start = 0;
	my $duration = $_end - $_start;
	my $found_file_count = 0;
	my @ret_list;
	
	my %time_hash;
	for( my $i = 0; $i < @{$_file_list}; ++$i )
	{
		$time_hash{$_file_list->[$i]->[1]} = $i;
	}
	
	foreach my $ts( sort {$a <=> $b} keys( %time_hash ) )
	{
		push( @ordered_list, $time_hash{$ts} );
	}
	
	my $file_count = scalar( @ordered_list );
	foreach my $idx( @ordered_list )
	{
		my $file_name = $_file_list->[$idx]->[0];
		my $file_start_time = $_file_list->[$idx]->[1];
		my $file_end_time = $_file_list->[$idx]->[2];
		
		if( $found_start )
		{
			if( $file_start_time <= $_end )
			{
				push( @ret_list, $file_name );
				++$found_file_count;
				if( ( $file_end_time - $_start ) > $duration )
				{
					last;
				}
			}
			else
			{
				last;
			}
		}
		elsif( ( $file_start_time <= $_start and $file_end_time >= $_start )
			or $file_start_time >= $_start )
		{
			$found_start = 1;
			push( @ret_list, $file_name );
			++$found_file_count;
			if( $file_end_time > $_end )
			{
				last;
			}
		}
	}
		
	if( wantarray )
	{
		return( @ret_list );
	}
	else
	{
		return( \@ret_list );
	}
}

sub true
{
	my $sub_name = 'true';
	
	my $arg = $_[0] || return( 0 );
	
	if( $arg =~ m/^1|y(?:es)?|t(?:rue)?$/i )
	{
		return( 1 );
	}
	else
	{
		return( 0 );
	}
}

sub false
{
	my $sub_name = 'false';
	
	my $arg = $_[0];
	
	if( $arg =~ m/^0|n(?:o)?|f(?:alse)?$/i )
	{
		return( 1 );
	}
	else
	{
		return( 0 );
	}
}

sub output_header
{
	my $sub_name = 'output_header';
	
	my $ret_string;
	my $cur_time = localtime();
	my $start_time = date_ymd( $config->{'report-start'} ) . " " .
		time_hms( $config->{'report-start'} );
	my $end_time = date_ymd( $config->{'report-end'} ) . " " .
		time_hms( $config->{'report-end'} );
	my $brosite = $config->{BRO_SITE_NAME};
	
	$ret_string = <<"END";

Site Report for $brosite, from $start_time to $end_time
generated on $cur_time
END
	
	return( \$ret_string );
}

sub output_system_summary
{
	my $sub_name = 'output_system_summary';
	
	my $ret_string;
	
	
	# Header
	$ret_string .= <<'END';
========================================================================
System Summary
========================================================================
END
	
	# Dropped packet summary
	# NOTE: this routine no longer works becase these are now in the 
	#	notice file, not the alarm file
	my $dropped_packets = Bro::Report::Alarm::output_droppedpackets();
$ret_string .= <<"END";

$dropped_packets
END
		
	return( \$ret_string );
}

sub output_connsummary
{
	my $sub_name = 'output_connsummary';
	
	my $ret_string = '';
	
	# Site success/fail connections
	my $total_connects = Bro::Report::Conn::output_successfailcount(), "\n";
	
	# Top 20 source format
	my $top_20_sources = Bro::Report::Conn::output_sourcecount( 20 );
	
	# Top 20 destination format
	my $top_20_destinations = Bro::Report::Conn::output_destcount( 20 );
	
	# Top 20 service format
	my $top_20_services = Bro::Report::Conn::output_servicecount( 20 );
	
	# Top 20 local email source format
	my $top_20_local_email = Bro::Report::Conn::output_localserviceusers( 'smtp', 20 );
	
	# Header
	$ret_string .= <<'END';
========================================================================
Connection Log Summary
========================================================================
END

	# Content
	$ret_string .= <<"END";
Site-wide connection statistics

$total_connects

Top 20 Sources

$top_20_sources

Top 20 Destinations

$top_20_destinations

Top 20 Local Email Senders

$top_20_local_email

Top 20 Services

$top_20_services
END
	
	return( \$ret_string );

}

sub output_incidentsummary
{
	my $sub_name = 'output_incidentsummary';
		
	my $ret_string = '';
	
	# Incident Summary Header
	$ret_string .= <<'END';
========================================================================
Summary
========================================================================
END
	
	if( my $data = Bro::Report::Alarm::output_incidentsummary() )
	{
		$ret_string .= $data . "\n";
	}
	
	if( my $data = Bro::Report::Alarm::output_scansummary() )
	{
		$ret_string .= $data . "\n";
	}
	
	if( my $data = Bro::Report::Alarm::output_signaturesummary() )
	{
		$ret_string .= $data . "\n";
	}
	
	return( \$ret_string );
}

sub output_incidentdetails
{
	my $sub_name = 'output_incidentdetails';
	
	my $ret_string = '';
	
	# Incident Details Header
	$ret_string .= <<'END';
========================================================================
Incident Details
========================================================================
END
	
	$ret_string .= Bro::Report::Alarm::output_incident();
	
	return( \$ret_string );    
}

sub output_scans
{
	my $sub_name = 'output_scans';
	
	my $ret_string;
	
	# Header
	$ret_string .= <<'END';
========================================================================
Scans
========================================================================
END
	
	$ret_string .= Bro::Report::Alarm::output_scans();
	$ret_string .= "\n";
	
	return( \$ret_string );
}

sub output_signaturedistribution
{
	my $sub_name = 'output_signaturedistribution';
	
	my $ret_string = '';
	
	# Header
	$ret_string .= <<'END';
========================================================================
Signature Distributions
========================================================================
END

	if( my $data = Bro::Report::Alarm::output_signaturedistribution( 20 ) )
	{
		$ret_string .= $data . "\n";
	}
	
	return( \$ret_string );
}

sub output_bytetransferpairs
{
	my $sub_name = 'output_bytetransferpairs';
	
	my $ret_string = '';
	
	# Header
	$ret_string .= <<'END';
========================================================================
Byte Transfer Pairs
========================================================================
END

	if( my $data = Bro::Report::Conn::output_bytetransferpairs( 20 ) )
	{
		$ret_string .= $data . "\n";
	}
	
	return( \$ret_string );
}

sub writereport
{
	my $sub_name = 'writereport';
	
	my $fh;
	if( ref( $_[0] ) eq 'GLOB' or ref( $_[0] ) eq 'IO' )
	{
		$fh = shift;
	}
	else
	{
		$fh = \*STDOUT;
	}
	
	my @args = @_;
	
	foreach my $part( @args )
	{
		if( !( print $fh $$part ) )
		{
			warn( "$sub_name, Unable to print to filehandle\n" );
			return( undef );
		}
	}
	
	return( 1 );
}


sub timezoneoffset
{
	my $sub_name = 'timezone';
	
	my $offset  = sprintf "%.1f", ( timegm( localtime ) - time );
	
	return( $offset );
}

sub usage
{
	my $sub_name = 'usage';
	
	my $usage_text = copyright();
	$usage_text = qq~$usage_text

Options passed to the program on the command line 
Command line reference
  --broconfig|-b      Alternate location containing Bro configuration data
  --report-range|-r   Length of time (in hours) from report-start to report
                      on. This will be overridden by report-end if specified.
                      (default: 24)
  --report-start|-s   The start time of the data to report on. See date format
                      below.  Values of yesterday and today are also
                      understood and default to to a start time of 00:30 hours
                      (default: yesterday)
  --report-end|-e     The end time of the data to report on.  This will
                      override report-range if specified.
  --max-hosts|-i
  --max-alarms|-m     The maximum number of alarms per host to include in a
                      report (default: 100)
  --temp              Alternate directory in which to write temp files
                      (default \$BROHOME/logs)
  --summary-only|-S   Output Connection Summaries only
  --usage|--help|-h   Summary of command line options
  --debug|-d          Specify the debug level from 0 to 5. (default: 1)
  --version           Output the version number to STDOUT
  --copyright         Output the copyright info to STDOUT
  
  Dates are specified as YEAR-MONTH-DAY"T"HOUR:MINUTE:SECOND
  Any time period not specified is assumed to be 0
  ( Examples: 2004-12-26T01:23:00, accurate to seconds field
              2004-12-26, Is the same as 2004-12-26T00:00:00
              2004-12-26T13, Is the same as 2004-12-26T13:00:00 )
~;
	
	return( $usage_text );
}

sub version
{
	my $sub_name = 'version';
	
	return( $VERSION );
}

sub copyright
{
	my $sub_name = 'copyright';
	
	my $copyright =
qq~s2b.pl
version $VERSION, Copyright (C) 2004 Lawrence Berkeley National Labs, NERSC
Written by Roger Winslow~;
	
	return( $copyright );
}

sub end_program
{
	my $sub_name = 'cleanup';
	
	my $exit_code = shift || 0;
	
	# Remove any temp files
	Bro::Report::tempfile( 'remove all' );
	
	exit( $exit_code );
}
