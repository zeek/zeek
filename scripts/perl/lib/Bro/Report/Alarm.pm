package Bro::Report::Alarm;

use strict;
require 5.006_001;
use Bro::Config( '$BRO_CONFIG' );
use Bro::Report qw( trimhostname iptoname swrite time_mdhm time_hms date_md
				standard_deviation getincidentnumber tempfile trimstring );
use Bro::Signature( 'getrules' );
use Bro::Log::Conn;

use vars qw( $VERSION
			$DEBUG
			$SCANS_MAX_COUNT
			$RPT_CACHE
			$BROHOME
			$SCAN_MAX_BYTES_RCV
			$SCAN_EVENT_REGEX
			$SCAN_EVENT_LIST
			$INCIDENT_EVENT_LIST
			$INCIDENT_EVENT_REGEX
			$INCIDENT_REPORTABLE_POLICY
			$REPORTABLE_EVENT_REGEX
			$NOTICE_TYPE_SCORES
			$NOTICE_TYPE_SCORES_FILE
			$SIGNATURE_ID_SCORES
			$SIGNATURE_ID_SCORES_FILE
			$ALARM_THRESHOLD
			$INCIDENT_TEMP_NUMBER
			$MAX_INCIDENT_CONN_LINES
			$SHOW_UNSUCCESSFUL_INCIDENTS
			$INCIDENT_SHOW_SUB_MESSAGE
			$INCIDENT_SHOW_SIGNATURE
			$ALARM_SUPPRESS_DUPLICATES );

# $Id: Alarm.pm 1433 2005-09-30 21:13:23Z tierney $
$VERSION = 1.20;
$SCANS_MAX_COUNT = 30;
$SCAN_MAX_BYTES_RCV = 20480;

$DEBUG = 0;
$INCIDENT_TEMP_NUMBER = 1;

# data for a report will be removed by it's respective function once the data
# has been called to output.  All report data in memory is held in
# variable $RPT_CACHE;

my %REPORT_MAP = ( 'scans' => { input => __PACKAGE__ . '::scans',
						output => __PACKAGE__ . '::output_scans', },
		'incidents' => { input => __PACKAGE__ . '::incident',
					output => __PACKAGE__ . '::output_incident', },
		'scan_summary' => { input => undef,
						output => __PACKAGE__ . '::output_scansummary', },
		'incident_summary' => { input => undef,
						output => __PACKAGE__ . '::output_incidentsummary', },
		'signature_summary' => { input => undef,
						output => __PACKAGE__ . '::output_signaturesummary', },
		'signature_distribution' => { input => __PACKAGE__ . '::signaturedistribution',
						output => __PACKAGE__ . '::output_signaturedistribution', },
		);

$NOTICE_TYPE_SCORES = {};
$SIGNATURE_ID_SCORES = {};

$NOTICE_TYPE_SCORES_FILE = $BRO_CONFIG->{BROHOME} . "/etc/alert_scores";
$SIGNATURE_ID_SCORES_FILE = $BRO_CONFIG->{BROHOME} . "/etc/signature_scores";

# Set the signature score list
setsignaturescores( $SIGNATURE_ID_SCORES_FILE );

# Set the notice_type score list
setnoticetypescores( $NOTICE_TYPE_SCORES_FILE );

# Current threshold limit, default is 100.
$ALARM_THRESHOLD = 100;

# This list defines what notice types will be treated as scans.
$SCAN_EVENT_LIST = {};

# Default list of notice types that are considered scan events
setreportablescan( 'PortScan', 'PasswordGuessing', 'AddressScan', 
	'MultipleSigResponders', 'MultipleSignatures', );

# See reportableincident and setreportableincident
$INCIDENT_EVENT_LIST = {};

# By default all notice types that are not scanned will be considered worth
# reporting and will generate an incident
setreportableincident( 'ScanSummary', 'AddressDropped', 'DEFAULT_ALLOW' );

$MAX_INCIDENT_CONN_LINES = 30;

# If and how should the unsuccessful incident data be displayed.
# Valid values are 'FIRST INSTANCE', 'ALL'
$SHOW_UNSUCCESSFUL_INCIDENTS = 'FIRST INSTANCE';

# Toggle whether the alarm sub_message should be included in the incident details
$INCIDENT_SHOW_SUB_MESSAGE = 1;

# Toggle whether the actual signature code block should be included in incident details
# when the notice type is SensitiveSignature
$INCIDENT_SHOW_SIGNATURE = 1;

# Toggle whether duplicate alarms should be suppressed inside an incident
$ALARM_SUPPRESS_DUPLICATES = 1;

### This is deprecated
my $DROPPED_PACKETS_REGEX = qr/([[:digit:]]+) packets dropped after filtering, ([[:digit:]]+) received, ([[:digit:]]+) on link/o;

sub scans
{
	my $sub_name = 'scans';
	
	my $_alarm_struc = $_[0] || return( undef );
	
	if( reportablescan( $_alarm_struc ) )
	{
		my $src_ip = Bro::Log::Alarm::source_ip( $_alarm_struc );
		push( @{$RPT_CACHE->{scans}->{$src_ip}->{ALARMS}}, $_alarm_struc );
	}
	
	return( 1 );
}

sub output_scans
{
	my $sub_name = 'output_scans';
	
	my $format = $_[1];
	my $total_scans = $RPT_CACHE->{scans}->{COUNT};
	my @results;
	my $ret_string;
	my $content = '';
	my $max_reason_length = 62;
	my @heading_names = ( 'Host', 'IP', );
	
	if( ! exists( $RPT_CACHE->{scans} ) )
	{
		return( undef );
	}
	
	if( ! $format )
	{
		$format = <<'END';
  Host:   @<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<  @<<<<<<<<<<<<<<
  Reason: @<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
  ~       @<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
  ~       @<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

END
	}
		
	# Classify the scans
	classifyscans();
	
	# Reorganize the scan by type
	my %scan_events_by_type;
	foreach my $h_ip( keys( %{$RPT_CACHE->{scans}} ) )
	{
		foreach my $alarm_struc( @{$RPT_CACHE->{scans}->{$h_ip}->{ALARMS}} )
		{
			my $notice_type = Bro::Log::Alarm::notice_type( $alarm_struc );
		        my $dest_ip = Bro::Log::Alarm::destination_addr( $alarm_struc ) ;
			push( @{$scan_events_by_type{$notice_type}}, $alarm_struc );
		}
	}
		
	# Make the content
	my $num_scans_output = 0;
	foreach my $event_type( keys( %scan_events_by_type ) )
	{
		foreach my $alarm_struc( @{$scan_events_by_type{$event_type}} )
		{
			my $h_ip = Bro::Log::Alarm::source_addr( $alarm_struc );
			my $h_name = trimhostname( iptoname( $h_ip ), 44, '>' );
			my $message;
			
			# Post process the messages for the following event types
			if( $event_type eq 'MultipleSignatures' )
			{
				$message = Bro::Log::Alarm::count( $alarm_struc ) .
					" different signatures triggered against " .
					Bro::Log::Alarm::destination_addr( $alarm_struc );
			}
			elsif( $event_type eq 'MultipleSigResponders' )
			{
				my $sig_event = Bro::Log::Alarm::message( $alarm_struc );
				my $sigid = Bro::Log::Alarm::sigid( $alarm_struc );
				my $c = Bro::Log::Alarm::count( $alarm_struc );
				$message = "Triggered signature $sigid: $sig_event across $c hosts";
			}
			else
			{
				$message = Bro::Log::Alarm::message( $alarm_struc );
			}
			
			# reduce to a max of three lines at $max_reason_length characters per line
			my @reason = trimstring( $message, $max_reason_length, 3 );
			
			$content .= swrite( $format, $h_name, $h_ip, @reason );
			++$num_scans_output;			
			if( $num_scans_output > $SCANS_MAX_COUNT )
			{
				last;
			}
		}
		if( $num_scans_output > $SCANS_MAX_COUNT )
		{
			last;
		}
	}
	
	if( length( $content ) < 10 )
	{
		$ret_string = "     No data to report\n";
	}
	else
	{
		$ret_string .= $content;
		if( $total_scans > $SCANS_MAX_COUNT )
		{
			my $num_not_displayed = $total_scans - $SCANS_MAX_COUNT;
			$ret_string .= <<"END"
			
    Maximum of $SCANS_MAX_COUNT scans are listed.
    There are another $num_not_displayed that are not displayed.
END
		}
	}
	
	# Clean up some memory
	delete( $RPT_CACHE->{scans} );
	
	return( $ret_string );
}

sub classifyscans
{
	my $sub_name = 'classifyscans';
	
	my $success_scans = 0;
	my $failed_scans = 0;
	
	if( exists( $RPT_CACHE->{scans}->{CLASSIFICATION_TOTALS} ) )
	{
		$success_scans = $RPT_CACHE->{scans}->{CLASSIFICATION_TOTALS}->{'SUCCESSFUL'};
		$failed_scans = $RPT_CACHE->{scans}->{CLASSIFICATION_TOTALS}->{'UNSUCCESSFUL'};
	}
	else
	{
		# Post process some scan types
		foreach my $host( keys( %{$RPT_CACHE->{scans}} ) )
		{
			my @new_alarm_list;
			my %ms;	# MultipleSignatures
			my %msr;	# MultipleSigResponders
			
			foreach my $alarm_struc( @{$RPT_CACHE->{scans}->{$host}->{ALARMS}} )
			{
				my $notice_type = Bro::Log::Alarm::notice_type( $alarm_struc );
				if( $notice_type eq 'MultipleSignatures' )
				{
					# Only keep the highest reported number for each pair
					my $src_ip = Bro::Log::Alarm::source_addr( $alarm_struc );
					my $dst_ip = Bro::Log::Alarm::destination_addr( $alarm_struc );
					if( exists( $ms{"$src_ip$dst_ip"} ) )
					{
						my $cur_count = Bro::Log::Alarm::count( $alarm_struc );
						if( $cur_count > Bro::Log::Alarm::count( $ms{"$src_ip$dst_ip"} ) )
						{
							$ms{"$src_ip$dst_ip"} = $alarm_struc;
						}
					}
					else
					{
						$ms{"$src_ip$dst_ip"} = $alarm_struc;
					}
				}
				elsif( $notice_type eq 'MultipleSigResponders' )
				{
					# Only keep the highest count for each offender
					my $src_ip = Bro::Log::Alarm::source_addr( $alarm_struc );
					if( exists( $msr{"$src_ip"} ) )
					{
						my $cur_count = Bro::Log::Alarm::count( $alarm_struc );
						if( $cur_count > Bro::Log::Alarm::count( $msr{"$src_ip"} ) )
						{
							$msr{"$src_ip"} = $alarm_struc;
						}
					}
					else
					{
						$msr{"$src_ip"} = $alarm_struc;
					}
				}
				else
				{
					push( @new_alarm_list, $alarm_struc );
				}
			}
			
			if( keys( %ms ) > 0 )
			{
				push( @new_alarm_list, values( %ms ) );
			}
			
			if( keys( %msr ) > 0 )
			{
				push( @new_alarm_list, values( %msr ) );
			}
			
			@{$RPT_CACHE->{scans}->{$host}->{ALARMS}} = @new_alarm_list;
		}
		# Figure out if the scan is worth reporting.
		foreach my $h_ip( keys( %{$RPT_CACHE->{scans}} ) )
		{
			my $is_success = 0;
			BLOCK: {
				# Check if there were any connections back to the offender
				if( $RPT_CACHE->{scans}->{$h_ip}->{CONNECTIONS_TO_OFFENDER} )
				{
					if( $DEBUG > 2 )
					{
						warn( "Scan events for $h_ip have be found worthy of reporting.  " . 
							$RPT_CACHE->{scans}->{$h_ip}->{CONNECTIONS_TO_OFFENDER} . 
							" connections were made back to the offender.\n");
					}
					$is_success = 1;
					last BLOCK;
				}
				
				if( exists( $RPT_CACHE->{scans}->{$h_ip}->{BYTES_RCV} ) )
				{
					foreach my $bytes_rcv( keys( %{$RPT_CACHE->{scans}->{$h_ip}->{BYTES_RCV}} ) )
					{
						if( $bytes_rcv > $SCAN_MAX_BYTES_RCV )
						{
							$is_success = 1;
							if( $DEBUG > 2 )
							{
								warn( "Scan events from source $h_ip have been found worthy of reporting." .
									"There was data over $SCAN_MAX_BYTES_RCV sent back to the host\n" );
							}
							last BLOCK;
						}
					}
				}
				
				# Figure out if the bytes sent by the offender is more than $num_deviations
				# deviations out from the standard deviation.
				if( $RPT_CACHE->{scans}->{$h_ip}->{BYTES_SENT} )
				{
					my $num_deviations = 3;
					my $std_dev = standard_deviation( $RPT_CACHE->{scans}->{$h_ip}->{BYTES_SENT} );
					my $max_deviation = sprintf( "%d", $std_dev * $num_deviations );
					my $max_val = 0;

					# Make sure that standard_deviation returned a valid value
					if( defined( $std_dev ) )
					{
						foreach my $num( keys( %{$RPT_CACHE->{scans}->{$h_ip}->{BYTES_SENT}} ) )
						{
							if( $num > $max_deviation )
							{
								$RPT_CACHE->{scans}->{$h_ip}->{SENT_DATA_DEVIATION} = 1;
								if( $DEBUG > 2 )
								{
									$max_val = $num;
								}
								last;
							}

							if( $DEBUG > 2 )
							{
								if( $num > $max_val )
								{
									$max_val = $num;
								}
							}
						}
					}
					else
					{
						# Not worthy of reporting
						$max_deviation = 'undef';
						if( $DEBUG > 2 )
						{
							warn( "Scan events from source $h_ip has been found not worthy of reporting.  " .
								"Not enough data for a standard deviation test.\n" );
						}
					}

					if( $RPT_CACHE->{scans}->{$h_ip}->{SENT_DATA_DEVIATION} )
					{
						# Report !
						$is_success = 1;
						if( $DEBUG > 2 )
						{
							warn( "Scan events from source $h_ip has been found worthy of reporting after " .
								"standard deviation test.  Max deviation was $max_deviation and max value ". 
								"was $max_val\n" );
						}
						last BLOCK;
					}
					else
					{
						# Not worthy of reporting
						delete( $RPT_CACHE->{scans}->{$h_ip} );
						if( $DEBUG > 2 )
						{
							warn( "Scan events from source $h_ip has been found not worthy of reporting after standard deviation test.\n" );
							warn( "Max deviation was $max_deviation and max value was $max_val\n" );
						}
					}
				}
				else
				{
					# Not worthy of reporting
					delete( $RPT_CACHE->{scans}->{$h_ip} );
					if( $DEBUG > 2 )
					{
						warn( "Scan events from source $h_ip has been found not worthy of reporting.\n" );
						warn( "Did not find any data transfered from host and none back to host.\n" );
					}
				}
			} # end BLOCK
			
			if( $is_success )
			{
				++$success_scans;
			}
			else
			{
				++$failed_scans;
			}
		}
		$RPT_CACHE->{scans}->{CLASSIFICATION_TOTALS}->{'SUCCESSFUL'} = $success_scans;
		$RPT_CACHE->{scans}->{CLASSIFICATION_TOTALS}->{'UNSUCCESSFUL'} = $failed_scans;
	}
	
	return( $success_scans, $failed_scans );
}

sub output_scansummary
{
	my $sub_name = 'output_scansummary';
	
	my $ret_string = '';
	
	if( ! exists( $RPT_CACHE->{scans} ) )
	{
		return( undef );
	}
	
	my( $successful_scans, $failed_scans ) = classifyscans();
	my $ret_string = <<"END";
  Scanning Hosts
    Successful            $successful_scans
    Unsuccessful          $failed_scans
END
	
	return( $ret_string );
}

sub incident
{
	my $sub_name = 'incident';
	
	my $_alarm_struc = $_[0] || return( undef );
	
	my $notice_type = Bro::Log::Alarm::notice_type( $_alarm_struc ) or return( undef );
	my $src_ip = Bro::Log::Alarm::source_addr( $_alarm_struc ) or return( undef );
	my $dest_ip = Bro::Log::Alarm::destination_addr( $_alarm_struc ) || '';
	
	# Find out if this is an incident worth tracking.
	if( reportableincident( $_alarm_struc ) )
	{
		my $timestamp = Bro::Log::Alarm::timestamp( $_alarm_struc );
		if( ! exists( $RPT_CACHE->{'incident'}->{OFFENDERS}->{$src_ip}->{VICTIMS}->{$dest_ip} ) )
		{
			$RPT_CACHE->{'incident'}->{OFFENDERS}->{$src_ip}->{VICTIMS}->{$dest_ip} = {};
		}
		
		my $data_root = $RPT_CACHE->{'incident'}->{OFFENDERS}->{$src_ip}->{VICTIMS}->{$dest_ip};
		
		# Put the alarm tag id in the list of tags to watch
		$data_root->{WATCH_TAG_IDS}->{Bro::Log::Alarm::tag( $_alarm_struc )} = 1;
		
		if( exists( $data_root->{BEGIN_TIMESTAMP} ) )
		{
			if( $timestamp < $data_root->{BEGIN_TIMESTAMP} )
			{
				$data_root->{BEGIN_TIMESTAMP} = $timestamp;
			}
		}
		else
		{
			$data_root->{BEGIN_TIMESTAMP} = $timestamp;
		}
		
		# Add the alarm to the list
		push( @{$data_root->{ALARMS}}, $_alarm_struc );
		
		if( $notice_type eq 'SensitiveSignature' )
		{
			my $add_score = 0;
			my $sig_id;
			
			# Find the signature id
			if( $sig_id = sigid( $_alarm_struc ) )
			{
				# Get the signature score
				$add_score = signaturescore( $sig_id );
			}
			
			push( @{$data_root->{SCORE}}, $add_score );
			
			# Add the sigid to the hash of known signature notices
			$RPT_CACHE->{'incident'}->{SIGNATURES}->{$sig_id} = 1;
		}
		else
		{
			# It's some other type of notice.  This is a general approach to
			# notices with no special handling.
			push( @{$data_root->{SCORE}}, noticetypescore( $notice_type ) );
		}
	}
	else
	{
		return( 0 );
	}
	
	return( 1 );
}

sub output_incident
{
	my $sub_name = 'output_incident';
	
	my $incident_struc = $_[0];
	my $conn_struc_array_ref = $_[1];
	my $_max_output_count = $_[2] || 3000;
	my @results;
	my $ret_string;
	my $incident_header;
	my $connection_pair_format;
	my $alarm_descr_format;
	my $alarm_time_dir_format;
	my $conn_top_format;
	my $conn_format;
	my $detail_legend;
	my $incident_count = 0;
	my $likely_successful = '';
	my $likely_unsuccessful = '';
	my $unknown = '';	
	my %unsuccessful_sig_ids;
	
	if( ! exists( $RPT_CACHE->{incident} ) )
	{
		return( undef );
	}
	
	# Legend to print at the top of the incident detail block
	$detail_legend = <<'END';
                  # legend for connection type #
                  ------------------------------
         C Connection Status
           # number corresponds to alarm triggered by the connection
           * successful connection, otherwise unsuccessful.
         I Initiatator of Connection
           > connection initiated by remote host
           < connection initiated by local host

END
	
	# Start of incident and the unique number associated with it
	$incident_header = <<'END';
------------------------------------------------------------------------
Incident      @<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< @>>>>>>>>>>>>>>>>>>>>>
------------------------
END
	
	# connection pair format
	$connection_pair_format = <<'END';
Remote Host:  @<<<<<<<<<<<<<<    @<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
 Local Host:  @<<<<<<<<<<<<<<    @<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

END
	
	# Alarm description output
	$alarm_descr_format = <<'END';
Alarm: @<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
  @<< @<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
~     @<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
~     Duplicates suppressed: @<<<<<<<<<<<
END

	# Alarm time and direction
	$alarm_time_dir_format = <<'END';
      @<<<<<<<<<<<<<                @>>>>>>>>>>>>>> -> @<<<<<<<<<<<<<<
~                                       @>>>>>>>>>> -> @<<<<<<<<<<
END
	
	# Header for the connection details
	$conn_top_format = <<"END";
Connections (only first $MAX_INCIDENT_CONN_LINES after alarm are listed)
-----------
                 time     byte   remote        local   byte
 date   time   duration transfer  port  C   I   port transfer  protocol
----- -------- -------- -------- ------ ------ ----- -------- ----------
END
	
	# Connection detail format
	$conn_format = <<'END';
@<<<< @<<<<<<< @>>>>>>> @>>>>>>> @>>>>> @<<<@> @>>>> @>>>>>>> @>>>>>>>>>
END
	
	# Check whether signatures are to be included in the report. If so parse
	# and store all signatures which are to be reported on.
	if( $INCIDENT_SHOW_SIGNATURE )
	{
		loadsignaturecode( keys( %{$RPT_CACHE->{incident}->{SIGNATURES}} ) );
	}
	
 	foreach my $offender( keys( %{$RPT_CACHE->{incident}->{OFFENDERS}} ) )
 	{
 		foreach my $__victim( keys( %{$RPT_CACHE->{incident}->{OFFENDERS}->{$offender}->{VICTIMS}} ) )
 		{
 			my $output;
 			my $__data = $RPT_CACHE->{incident}->{OFFENDERS}->{$offender}->{VICTIMS}->{$__victim};
 			if( $__data->{CLASS} eq 'LIKELY SUCCESSFUL' )
 			{
 				$output = \$likely_successful;
 			}
 			elsif( $__data->{CLASS} eq 'UNKNOWN' )
 			{
 				$output = \$unknown;
 			}
 			elsif( $__data->{CLASS} eq 'LIKELY UNSUCCESSFUL' and 
 				$SHOW_UNSUCCESSFUL_INCIDENTS )
 			{
 				$output = \$likely_unsuccessful;
 				
 				if( $SHOW_UNSUCCESSFUL_INCIDENTS eq 'FIRST INSTANCE' )
 				{
 					my @new_alarm_list;
 					foreach my $alarm( @{$__data->{ALARMS}} )
 					{
 						if( Bro::Log::Alarm::notice_type( $alarm ) eq 'SensitiveSignature' )
 						{
 							if( ! exists( $unsuccessful_sig_ids{Bro::Log::Alarm::sigid( $alarm )} ) )
 							{
 								$unsuccessful_sig_ids{Bro::Log::Alarm::sigid( $alarm )} = 1;
 								push( @new_alarm_list, $alarm );
 							}
 						}
 						else
 						{
 							push( @new_alarm_list, $alarm );
 						}
 					}
 					
 					if( scalar( @new_alarm_list ) < 1 )
 					{
 						next;
 					}
 					else
 					{
 						$__data->{ALARMS} = \@new_alarm_list;
 					}
 				}
 			}
 			else
 			{
 				next;
 			}
			
			my @alarms;
			my %alarm_times;
			# Sort the alarms in ascending order (probably already sorted but make sure)
			for( my $a_idx = 0; $a_idx < @{$__data->{ALARMS}}; ++$a_idx )
			{
				my $timestamp = Bro::Log::Alarm::timestamp( $__data->{ALARMS}->[$a_idx] );
				push( @{$alarm_times{$timestamp}}, $a_idx );
			}
			
			foreach my $ts( sort( {$a <=> $b} keys( %alarm_times ) ) )
			{
				foreach my $idx( @{$alarm_times{$ts}} )
				{
					push( @alarms, $__data->{ALARMS}->[$idx] );
				}
			}
			
			undef( %alarm_times );
			
			# If duplicate suppression is on then remove duplicate alarms and
			# set the duplicate count on the alarm that will be displayed.
			if( $ALARM_SUPPRESS_DUPLICATES and scalar( @alarms ) > 1 )
			{
				my @new_alarm_list;
				my $new_alarm_idx = 0;
				
				# prime the new list with the first one in the current list
				# of alarms.
				$new_alarm_list[0] = $alarms[0];
				
				for( my $i = 1; $i < scalar( @alarms ); ++$i )
				{
					if( Bro::Log::Alarm::notice_type( $new_alarm_list[$new_alarm_idx] ) eq
						Bro::Log::Alarm::notice_type( $alarms[$i] ) )
					{
						if( Bro::Log::Alarm::message( $new_alarm_list[$new_alarm_idx] ) ne
							Bro::Log::Alarm::message( $alarms[$i] ) )
						{
							++$new_alarm_idx;
							$new_alarm_list[$new_alarm_idx] = $alarms[$i];
						}
						else
						{
							++$new_alarm_list[$new_alarm_idx]->{report_duplicate_count};
						}
					}
					else
					{
						++$new_alarm_idx;
						$new_alarm_list[$new_alarm_idx] = $alarms[$i];
					}
				}
				
				@alarms = @new_alarm_list;
			}
			
			# Store conn strucs for writting later
			my @conn_strucs;
			
			my $begin_timestamp = $__data->{BEGIN_TIMESTAMP};
			push( @conn_strucs, incidentconndata( $offender, $__victim, $begin_timestamp ) );
			
			my $incident_id = $BRO_CONFIG->{BRO_SITE_NAME} . '-' . sprintf( "%06d", getincidentnumber() );
			my $victim_hostname = iptoname( $__victim );
			my $offender_hostname = iptoname( $offender );
			my %alarm_times;
			my $last_alarm_idx = 0;
			my $conn_details_output;
			my %conn_reference;
			my $conn_ref_count = 1;
			
			$$output .= swrite( $incident_header, $incident_id );
			# $$output .= swrite( $incident_header, $incident_id, $__data->{CLASS} );
			
			# If there is no connection data then skip the connection data ties
			if( ! $conn_strucs[0] )
			{
				# No connection data
				
				$conn_details_output .= $conn_top_format;
				$conn_details_output .= "    No connection data available\n";
			}
			else
			{

				my $local_ip;
				my $local_hostname;
				my $remote_ip;
				my $remote_hostname;
				
				# Figure out which host is local, victim or offender
				my $source_net = Bro::Log::Conn::source_network( $conn_strucs[0] );
				if( $source_net eq 'L' )
				{
					if( Bro::Log::Conn::source_ip( $conn_strucs[0] ) eq $offender )
					{
						$remote_ip = $__victim;
						$remote_hostname = $victim_hostname;
						$local_ip = $offender;
						$local_hostname = $offender_hostname;
					}
					else
					{
						$remote_ip = $offender;
						$remote_hostname = $offender_hostname;
						$local_ip = $__victim;
						$local_hostname = $victim_hostname;
					}
				}
				else
				{
					if( Bro::Log::Conn::source_ip( $conn_strucs[0] ) eq $offender )
					{
						$remote_ip = $offender;
						$remote_hostname = $offender_hostname;
						$local_ip = $__victim;
						$local_hostname = $victim_hostname;
					}
					else
					{
						$remote_ip = $__victim;
						$remote_hostname = $victim_hostname;
						$local_ip = $offender;
						$local_hostname = $offender_hostname;
					}
				}
				
				# Trim the hostnames down if needed
				$local_hostname = trimhostname( $local_hostname ,39 , '<' );
				$remote_hostname = trimhostname( $remote_hostname ,39 , '>' );
				
				$$output .= swrite( $connection_pair_format, $remote_ip, $remote_hostname,
								$local_ip, $local_hostname );

				# Delay writing of the details to the returned string
				$conn_details_output .= $conn_top_format;
				
				# This is a copy of @alarms and will be drained as each is matched
				my @tie_alarms = @alarms;
				
				foreach my $conn_struc( @conn_strucs )
				{
					my $timestamp = Bro::Log::Conn::timestamp( $conn_struc );
					my $date = date_md( $timestamp );
					my $time = time_hms( $timestamp );
					my $duration = Bro::Log::Conn::duration( $conn_struc, 'raw' );
					my $service = Bro::Log::Conn::service( $conn_struc );
					my $remote_bytes;
					my $remote_port;
					my $local_bytes;
					my $local_port;
					my $direction;

					if( Bro::Log::Conn::source_ip( $conn_struc ) eq $remote_ip )
					{
						$remote_bytes = Bro::Log::Conn::source_bytes( $conn_struc, 'raw' );
						$remote_port = Bro::Log::Conn::source_port( $conn_struc );
						$local_bytes = Bro::Log::Conn::destination_bytes( $conn_struc, 'raw' );
						$local_port = Bro::Log::Conn::destination_port( $conn_struc );
						$direction = ' >';
					}
					else
					{
						$remote_bytes = Bro::Log::Conn::destination_bytes( $conn_struc, 'raw' );
						$remote_port = Bro::Log::Conn::destination_port( $conn_struc );
						$local_bytes = Bro::Log::Conn::source_bytes( $conn_struc, 'raw' );
						$local_port = Bro::Log::Conn::source_port( $conn_struc );
						$direction = '< ';
					}

					my $conn_stat;
					
					# Tie connection and alarm data together if possible
					# Also mark connections (un)successful
					for( my $i = 0; $i < @tie_alarms; ++$i )
					{
						# If the alarm has already been matched then it is not
						# defined, just skip over it.
						if( ! $tie_alarms[$i] )
						{
							next;
						}
						
						my $alarm_time = Bro::Log::Alarm::timestamp( $tie_alarms[$i] );
						if( my $tag_id = Bro::Log::Alarm::tag( $tie_alarms[$i] ) )
						{
							# Alarm times must fall within at least
							# 12 minutes of a connection to match up.
							# This is to help prevent false matches
							# if tag ids reset do due restarts or crashes.
							# It is still possible to incorrectly match
							# if the tag ids are reset often.
							if( Bro::Log::Conn::range( $conn_struc, $alarm_time, 720 ) and
								Bro::Log::Conn::containstag( $conn_struc, $tag_id ) )
							{
								$conn_reference{$i} = $conn_ref_count;
								$conn_stat = $conn_ref_count;
								$tie_alarms[$i] = undef;
							}
						}
					}

					if( $conn_stat )
					{
						++$conn_ref_count;
					}
					elsif( Bro::Log::Conn::connectsucceed( $conn_struc ) )
					{
						$conn_stat = '*';
					}
					else
					{
						$conn_stat = '';
					}

					$conn_details_output .= swrite( $conn_format, $date, $time, $duration,
						$remote_bytes, $remote_port, $conn_stat, $direction,
						$local_port, $local_bytes, $service );
				}
			}
			
			# Now go back through and create the alarms section
			for( my $a_idx = 0; $a_idx < @alarms; ++$a_idx )
			{
				my $reference_idx;
				my $offender_port;
				my $__victim_port;
				
				# Get the source/dest ports and figure out which is local/remote
				if( Bro::Log::Alarm::source_addr( $alarms[$a_idx] ) eq $offender )
				{
					$offender_port = Bro::Log::Alarm::source_port( $alarms[$a_idx] );
					$__victim_port = Bro::Log::Alarm::destination_port( $alarms[$a_idx] );
				}
				else
				{
					$__victim_port = Bro::Log::Alarm::source_port( $alarms[$a_idx] );
					$offender_port = Bro::Log::Alarm::destination_port( $alarms[$a_idx] );
				}
				
				if( exists( $conn_reference{$a_idx} ) )
				{
					$reference_idx = $conn_reference{$a_idx};
				}
				else
				{
					$reference_idx = '';
				}
				
				my $notice_type = Bro::Log::Alarm::notice_type( $alarms[$a_idx] );
				my $event_msg;
				if( $notice_type eq 'SensitiveSignature' )
				{
					$event_msg .= Bro::Log::Alarm::sigid( $alarms[$a_idx] );
					$event_msg .= ": " . Bro::Log::Alarm::message( $alarms[$a_idx] );
				}
				else
				{
					$event_msg .= Bro::Log::Alarm::message( $alarms[$a_idx] );
				}
				
				# Make sure that the event message has some value otherwise
				# add something default
				if( ! $event_msg )
				{
					$event_msg = '(no event message available)';
				}
				
				my( $message1, $message2 ) = trimstring( $event_msg, 66, 2 );
				my $duplicate_count;
				
				# Check for duplicate counts if applicable
				if( $alarms[$a_idx]->{report_duplicate_count} )
				{
					$duplicate_count = $alarms[$a_idx]->{report_duplicate_count};
				}
				
				my $time = date_md( Bro::Log::Alarm::timestamp( $alarms[$a_idx] ) ) .
					' '. time_hms( Bro::Log::Alarm::timestamp( $alarms[$a_idx] ) );
				$$output .= swrite( $alarm_descr_format, $notice_type, $reference_idx,
								$message1, $message2, $duplicate_count );
				$$output .= swrite( $alarm_time_dir_format, $time, $offender,
					$__victim, $offender_port, $__victim_port );
								
				# Attach the signature code if the notice type is SensitiveSignature
				# and $INCIDENT_SHOW_SIGNATURE is true
				if( $notice_type eq 'SensitiveSignature' and $INCIDENT_SHOW_SIGNATURE )
				{
					$$output .= "      signature code:\n";
					if( my @parts = split( /\n/, signaturecode( Bro::Log::Alarm::sigid( $alarms[$a_idx] ) ) ) )
					{
						foreach my $_line( @parts )
						{
							$$output .= "        $_line\n";
						}
					}
					else
					{
						$$output .= "        (Not available)\n";
					}
				}
				
				# Attach sub message if available and option set
				if( Bro::Log::Alarm::sub_message( $alarms[$a_idx] ) and $INCIDENT_SHOW_SUB_MESSAGE )
				{
					if( $notice_type eq 'SensitiveSignature' )
					{
						$$output .= "      payload:\n";	
					}
					else
					{
						$$output .= "      sub message:\n";	
					}
					
					foreach my $sub_message( trimstring( Bro::Log::Alarm::sub_message( $alarms[$a_idx] ), 65 ) )
					{
						$$output .= "        $sub_message\n";
					}
				}
				# Add a newline between alarms
				$$output .= "\n";
			}
			
			$$output .= $conn_details_output;
			
			$$output .= "-----------------------------\n\n\n";
			
			++$incident_count;
		}
	}
	
	if( $incident_count < 1 )
	{
		$ret_string = "     No data to report\n";
	}
	else
	{
		$ret_string .= $detail_legend . $likely_successful . $unknown . $likely_unsuccessful;
	}
	
	# Clean up some memory
	delete( $RPT_CACHE->{incident} );
	
	return( $ret_string );
}

sub classifyincidents
{
	my $sub_name = 'classifyincidents';
	
	my $success = 0;
	my $unsuccess = 0;
	my $unknown = 0;
	
	if( ! exists( $RPT_CACHE->{incident}->{OFFENDERS} ) )
	{
		return( undef );
	}
	
	if( exists( $RPT_CACHE->{incident}->{CLASSIFICATION_TOTALS} ) )
	{
		$success = $RPT_CACHE->{incident}->{CLASSIFICATION_TOTALS}->{'LIKELY SUCCESSFUL'};
		$unsuccess = $RPT_CACHE->{incident}->{CLASSIFICATION_TOTALS}->{'LIKELY UNSUCCESSFUL'};
		$unknown = $RPT_CACHE->{incident}->{CLASSIFICATION_TOTALS}->{'UNKNOWN'};
	}
	else
	{
		foreach my $offender( keys( %{$RPT_CACHE->{incident}->{OFFENDERS}} ) )
		{
			if( ! exists( $RPT_CACHE->{incident}->{OFFENDERS}->{$offender}->{VICTIMS} ) )
			{
				if( $DEBUG > 2 )
				{
					warn( __PACKAGE__ . "::$sub_name, No victims listed for offender $offender\n" );
				}
				next;
			}
			
			while( my ( $__victim, $__data ) = each( %{$RPT_CACHE->{incident}->{OFFENDERS}->{$offender}->{VICTIMS}} ) )
			{
				my $BIGGEST_SCORE;	# store the largest score found for incident
				
				if( exists( $__data->{SCORE} ) )
				{
					$BIGGEST_SCORE = ( sort( {$b <=> $a} @{$__data->{SCORE}} ) )[0];
				}
				else
				{
					if( $DEBUG > 2 )
					{
						warn( __PACKAGE__ . "::$sub_name, No scores set for offender $offender.  Defaulting to 0\n" );
					}
					
					push( @{$__data->{SCORE}}, 0 );
					$BIGGEST_SCORE = 0;
				}
				
				my $likelyhood;
				if( $BIGGEST_SCORE >= $ALARM_THRESHOLD )
				{
					$__data->{CLASS} = 'LIKELY SUCCESSFUL';
					++$success;
				}
				elsif( $BIGGEST_SCORE == 0 )
				{
					$__data->{CLASS} = 'UNKNOWN';
					++$unknown;
				}
				else
				{
					$__data->{CLASS} = 'LIKELY UNSUCCESSFUL';
					++$unsuccess;
				}
			}
		}
		$RPT_CACHE->{incident}->{CLASSIFICATION_TOTALS}->{'LIKELY SUCCESSFUL'} = $success;
		$RPT_CACHE->{incident}->{CLASSIFICATION_TOTALS}->{'LIKELY UNSUCCESSFUL'} = $unsuccess;
		$RPT_CACHE->{incident}->{CLASSIFICATION_TOTALS}->{'UNKNOWN'} = $unknown;
	}	
	
	return( $success, $unsuccess, $unknown );
}

sub output_incidentsummary
{
	my $sub_name = 'output_incidentsummary';
	
	# NOTE: An incident is defined as one or more alarms that occur between two ip
	# addresses.
	
	my $ret_string = '';
	
	if( ! exists( $RPT_CACHE->{incident} ) )
	{
		return( undef );
	}
	
	my( $success, $unsuccess, $unknown ) = classifyincidents();
        my $total_incidents = $success + $unknown + $unsuccess;
	
	$ret_string = <<"END";
  Incident Count: $total_incidents
END
	
	return( $ret_string );
}

sub output_signaturesummary
{
	my $sub_name = 'output_signaturesummary';
	
	my $ret_string = '';
	my $total_sigs = 0;
	my $unique_sigs = 0;
	my $unique_sources = 0;
	my $unique_destinations = 0;
	my $src_dest_pairs = 0;
	
	my %source_dest_pairs;
	my %sources;
	my %dests;
	
	if( ! $RPT_CACHE->{signaturedistribution} )
	{
		return( undef );
	}
	
	foreach my $sigid( keys( %{$RPT_CACHE->{signaturedistribution}} ) )
	{
		$total_sigs += $RPT_CACHE->{signaturedistribution}->{$sigid}->{COUNT};
		++$unique_sigs;
		foreach my $src( keys( %{$RPT_CACHE->{signaturedistribution}->{$sigid}->{SOURCE}} ) )
		{
			$sources{$src} = 1;
		}
		
		foreach my $dest( keys( %{$RPT_CACHE->{signaturedistribution}->{$sigid}->{DEST}} ) )
		{
			$dests{$dest} = 1;
		}
		
		foreach my $pair( keys( %{$RPT_CACHE->{signaturedistribution}->{$sigid}->{PAIR}} ) )
		{
			$source_dest_pairs{$pair} = 1;
		}
	}
	
	if( my $total = keys( %sources ) )
	{
		$unique_sources = $total;
	}
	
	if( my $total = keys( %dests ) )
	{
		$unique_destinations = $total;
	}
	
	if( my $total = keys( %source_dest_pairs ) )
	{
		$src_dest_pairs = $total;
	}
	
	my $ret_string = <<"END";
  Signature Summary
    Total signatures          $total_sigs
    Unique signatures         $unique_sigs
    Unique sources            $unique_sources
    Unique destinations       $unique_destinations
    Unique source/dest pairs  $src_dest_pairs
END
		
	return( $ret_string );
}

sub signaturedistribution
{
	my $sub_name = 'signaturedistribution';
	
	my $alarm_struc = $_[0] || return( undef );
	
	if( Bro::Log::Alarm::notice_type( $alarm_struc ) eq 'SensitiveSignature' )
	{
		my $sigid = Bro::Log::Alarm::sigid( $alarm_struc );
		my $src_ip = Bro::Log::Alarm::source_addr( $alarm_struc );
		my $dst_ip = Bro::Log::Alarm::destination_addr( $alarm_struc );
		
		if( $sigid and $src_ip and $dst_ip )
		{
			++$RPT_CACHE->{signaturedistribution}->{$sigid}->{SOURCE}->{$src_ip};
			++$RPT_CACHE->{signaturedistribution}->{$sigid}->{DEST}->{$dst_ip};
			++$RPT_CACHE->{signaturedistribution}->{$sigid}->{PAIR}->{"$src_ip-$dst_ip"};
			++$RPT_CACHE->{signaturedistribution}->{$sigid}->{COUNT};
		}
	}
}

sub output_signaturedistribution
{
	my $sub_name = 'output_signaturedistribution';
	
	my $max_output = $_[0] || 20;
	my %reversed_hash;
	my $ret_string = '';
	my @ordered_list;
	
	my $signaturecount_header = <<'END';
                                        Unique      Unique     Unique
  Signature ID                Count     Sources     Dests      Pairs
  ------------------------  ---------  ---------  ---------  -----------
END
	my $signaturecount_format = <<'END';
  @<<<<<<<<<<<<<<<<<<<<<<<  @<<<<<<<<  @<<<<<<<<  @<<<<<<<<  @<<<<<<<<<<
END

	if( ! exists( $RPT_CACHE->{signaturedistribution} ) )
	{
		$ret_string = "  No data to report\n";
		return( $ret_string );
	}
	
	# Reverse the hash
	foreach my $sigid( keys( %{$RPT_CACHE->{signaturedistribution}} ) )
	{
		push( @{$reversed_hash{$RPT_CACHE->{signaturedistribution}->{$sigid}->{COUNT}}}, $sigid );
	}
	
	# Sort and then set to $ret_string
	@ordered_list = sort( { $b<=>$a } keys( %reversed_hash ) );
	
	my $i = 0;
	while( defined( my $count = shift( @ordered_list ) ) and $i < $max_output )
	{
		foreach my $sigid( @{$reversed_hash{$count}} )
		{
			my $source_count = 0;
			my $dest_count = 0;
			my $pair_count = 0;
			
			$source_count = keys( %{$RPT_CACHE->{signaturedistribution}->{$sigid}->{SOURCE}} );
			$dest_count = keys( %{$RPT_CACHE->{signaturedistribution}->{$sigid}->{DEST}} );
			$pair_count = keys( %{$RPT_CACHE->{signaturedistribution}->{$sigid}->{PAIR}} );
			
			$ret_string .= swrite( $signaturecount_format,
							$sigid,
							$count,
							$source_count,
							$dest_count,
							$pair_count, );
			++$i;
			if( !( $i < $max_output ) )
			{
				last;
			}
		}
	}
	
	if( length( $ret_string ) < 1 )
	{
		$ret_string = "  No data to report\n";
	}
	else
	{
		$ret_string = $signaturecount_header . $ret_string;
	}
	
	return( $ret_string );
}

######### This report is very misleading.  I left it in only as an example but
# it's results are not accurate.
sub droppedpackets
{
	my $sub_name = 'droppedpackets';
	
	my $alarm_struc = $_[0] || return( undef );
	
	if( Bro::Log::Alarm::notice_type( $alarm_struc ) eq 'DroppedPackets' )
	{
		if( Bro::Log::Alarm::message( $alarm_struc ) =~ $DROPPED_PACKETS_REGEX )
		{
			my $dropped = $1 || 0;
			my $packets_since_last_notice = $3 || 0;
			$RPT_CACHE->{droppedpackets}->{DROPPED} += $dropped;
			$RPT_CACHE->{droppedpackets}->{RECIEVED} += $packets_since_last_notice;
		}
		else
		{
			return( undef );
		}
		return( 1 );
	}
	else
	{
		return( 0 );
	}
}

######### This report is very misleading.  I left it in only as an example but
# it's results are not accurate.
sub output_droppedpackets
{
	my $sub_name = 'output_droppedpackets';
	
	my $dropped;
	my $recieved;
	my $percent_dropped;
	my $ret_string;
	
	if( exists( $RPT_CACHE->{droppedpackets} ) and 
		$RPT_CACHE->{droppedpackets}->{RECIEVED} > 0 )
	{
		$dropped = $RPT_CACHE->{droppedpackets}->{DROPPED};
		$recieved = $RPT_CACHE->{droppedpackets}->{RECIEVED} + $dropped;
		
		if( $dropped > 0 )
		{
			$percent_dropped = sprintf( "%.4f", ( $dropped / $recieved ) * 100 );
		}
		else
		{
			$percent_dropped = '0%';
		}
	}
	else
	{
		return( undef );
	}
	
	$ret_string = <<"END";
  Dropped Packets
    Packets Recieved: $recieved
    Packets Dropped:  $dropped
    Percent Dropped: $percent_dropped\%
END
	
	# Clean up some memory
	delete( $RPT_CACHE->{droppedpackets} );
	
	return( $ret_string );

}

sub sigid
{
	my $sub_name = 'sigid';
	
	my $_alarm_struc = $_[0];
	my $ret_val;
	
	my $ret_val = Bro::Log::Alarm::filename( $_alarm_struc );
	
	return( $ret_val );	
}

sub setsignaturescores
{
	my $sub_name = 'setsignaturescores';
	
	my $_sigid = $_[0];
	my $ret_hash = {};
	
	if( open( INFILE, $SIGNATURE_ID_SCORES_FILE ) )
	{
		while( defined( my $line = <INFILE> ) )
		{
			if( $line !~ m/^[[:space:]]*\#/ )
			{
				my( $key, $val, $junk ) = split( " ", $line, 3 );
				$ret_hash->{$key} = $val;
			}
		}
	}
	else
	{
		warn( "Unable to open signature score file at $SIGNATURE_ID_SCORES_FILE\n" );
		return( undef );
	}
	
	# Capitalize the _DEFAULT_ parameter if not already
	if( exists( $ret_hash->{'_default_'} ) )
	{
		$ret_hash->{'_DEFAULT_'} = $ret_hash->{'_default_'};
		delete( $ret_hash->{'_default_'} );
	}
	
	# Make sure that a default has been set
	if( ! exists( $ret_hash->{'_DEFAULT_'} ) or
		$ret_hash->{'_DEFAULT_'} !~ m/^[[:digit:]]+$/ )
	{
		$ret_hash->{'_DEFAULT_'} = 5;
	}
	
	close( INFILE );
	
	# Set the package variable to the signature scores taken from the file
	$SIGNATURE_ID_SCORES = $ret_hash;
	
	if( $DEBUG > 3 )
	{
		warn( "Current scores for signature ids\n" );
		while( my( $key, $val ) = each( %{$ret_hash} ) )
		{
			warn( "SIGID: $key => SCORE: $val\n" );
		}
		warn( "\n" );
	}
	
	return( $ret_hash );
}

sub setnoticetypescores
{
	my $sub_name = 'setnoticetypescores';
	
	my $_sigid = $_[0];
	my $ret_hash = {};
	
	if( open( INFILE, $NOTICE_TYPE_SCORES_FILE ) )
	{
		while( defined( my $line = <INFILE> ) )
		{
			if( $line !~ m/^[[:space:]]*\#/ )
			{
				my( $key, $val, $junk ) = split( " ", $line, 3 );
				$ret_hash->{$key} = $val;
			}
		}
	}
	else
	{
		warn( "Unable to open notice_type score file at $NOTICE_TYPE_SCORES_FILE\n" );
		return( undef );
	}
	
	# Capitalize the _DEFAULT_ parameter if not already
	if( exists( $ret_hash->{'_default_'} ) )
	{
		$ret_hash->{'_DEFAULT_'} = $ret_hash->{'_default_'};
		delete( $ret_hash->{'_default_'} );
	}
	
	# Make sure that a default has been set
	if( ! exists( $ret_hash->{'_DEFAULT_'} ) or
		$ret_hash->{'_DEFAULT_'} !~ m/^[[:digit:]]+$/ )
	{
		$ret_hash->{'_DEFAULT_'} = 0;
	}
	
	close( INFILE );
	
	# Set the package variable to the signature scores taken from the file
	$NOTICE_TYPE_SCORES = $ret_hash;
	
	if( $DEBUG > 3 )
	{
		warn( "Current scores for notice types\n" );
		while( my( $key, $val ) = each( %{$ret_hash} ) )
		{
			warn( "NOTICE_TYPE: $key => SCORE: $val\n" );
		}
		warn( "\n" );
	}
	
	return( $ret_hash );
}

sub signaturescore
{
	my $sub_name = 'signaturescore';
	
	my $sigid = $_[0] || '_DEFAULT_';
	my $ret_val;
	
	if( exists( $SIGNATURE_ID_SCORES->{$sigid} ) )
	{
		$ret_val = $SIGNATURE_ID_SCORES->{$sigid};
	}
	else
	{
		$ret_val = $SIGNATURE_ID_SCORES->{'_DEFAULT_'};
	}
	
	return( $ret_val );
}


sub noticetypescore
{
	my $sub_name = 'noticetypescore';
	
	my $notice_type = $_[0] || '_DEFAULT_';
	my $ret_val;
	
	if( exists( $NOTICE_TYPE_SCORES->{$notice_type} ) )
	{
		$ret_val = $NOTICE_TYPE_SCORES->{$notice_type};
	}
	else
	{
		$ret_val = $NOTICE_TYPE_SCORES->{'_DEFAULT_'};
	}
	
	return( $ret_val );
}
sub addconndata
{
	my $sub_name = 'addconndata';
	# The purpose of this function is to add additional data to report
	# parts that can use it.  The data can be used to weight probabilities
	# or add data to a report.
	
	# Filehandle which contains connection data.
	my $conn_struc = $_[0] || return( undef );	# ref to Bro::Log::Conn struc
	my $conn_line = $_[1] || return( undef );	# ref to string
	my $add_override = $_[2];
	
	# Scans really only mean something if a successful connection was made
	# or an annomylous conection out of the scan was made.
	my $src_ip = Bro::Log::Conn::source_ip( $conn_struc );
	my $dest_ip = Bro::Log::Conn::destination_ip( $conn_struc );
	my $service = Bro::Log::Conn::service( $conn_struc );
	my $success_connect = Bro::Log::Conn::connectsucceed( $conn_struc );
	my $src_net = Bro::Log::Conn::source_network( $conn_struc );
	if( exists( $RPT_CACHE->{scans}->{$src_ip} ) and
		$RPT_CACHE->{scans}->{$src_ip}->{CONNECTIONS_TO_OFFENDER} )
	{
		if( $service !~ m/^dns|ident$/ and
				$src_net eq 'L' and
				$success_connect )
		{
			++$RPT_CACHE->{scans}->{$dest_ip}->{CONNECTIONS_TO_OFFENDER};
		}
	}
	# If a scanner and not a service to ignore and bytes >= 0 then store
	# the byte count for a post collection standard deviation test.
	elsif( exists( $RPT_CACHE->{scans}->{$src_ip} ) )
	{
		my $src_bytes = Bro::Log::Conn::source_bytes( $conn_struc );
		my $dest_bytes = Bro::Log::Conn::destination_bytes( $conn_struc );
		if( $service !~ m/^dns|ident$/ )
		{
			if( $src_bytes >= 0 )
			{
				++$RPT_CACHE->{scans}->{$src_ip}->{BYTES_SENT}->{$src_bytes};
				++$RPT_CACHE->{scans}->{$src_ip}->{BYTES_RCV}->{$dest_bytes};
			}
		}
	}
	# If a scanner is the destination and our local_net is the orginator
	# of the connection this may be very interesting.
	elsif( exists( $RPT_CACHE->{scans}->{$dest_ip} ) and
		$service !~ m/^dns|ident$/ and
		$src_net eq 'L' )
	{
		++$RPT_CACHE->{scans}->{$dest_ip}->{CONNECTIONS_TO_OFFENDER};
	}
	
	# Add connection data to incidents
	my $offender_address;
	my $victim_address;
	if( exists( $RPT_CACHE->{incident}->{OFFENDERS}->{$src_ip} ) )
	{
		# Does the connection data contain the victim address
		if( exists( $RPT_CACHE->{incident}->{OFFENDERS}->{$src_ip}->{VICTIMS}->{$dest_ip} ) )
		{
			$offender_address = $src_ip;
			$victim_address = $dest_ip;
		}
	}
	elsif( exists( $RPT_CACHE->{incident}->{OFFENDERS}->{$dest_ip} ) )
	{
		# Does the connection data contain the victim address
		if( exists( $RPT_CACHE->{incident}->{OFFENDERS}->{$dest_ip}->{VICTIMS}->{$src_ip} ) )
		{
			$offender_address = $dest_ip;
			$victim_address = $src_ip;
			if( $service !~ m/^dns|ident$/ )
			{
				# This means there was a connection from the victim back to the 
				# offender.  Most likely very interesting.
				push( @{$RPT_CACHE->{incident}->{OFFENDERS}->{$dest_ip}->{VICTIMS}->{$src_ip}->{SCORE}}, 100 );
			}
		}
	}
	
	# If the offender address was found in the connection struc then do a few
	# more checks on whether to store the data for later retrieval.
	if( $offender_address )
	{
		if( ! $victim_address )
		{
			$victim_address = '';
		}
		
		my $temp_fh = $RPT_CACHE->{incident}->{'TEMP_FILE_HANDLE'};
		my $incident_data;
		
		if( exists( $RPT_CACHE->{incident}->{OFFENDERS}->{$offender_address} ) and
			exists( $RPT_CACHE->{incident}->{OFFENDERS}->{$offender_address}->{VICTIMS}->{$victim_address} ) )
		{
			my $data_root = $RPT_CACHE->{incident}->{OFFENDERS}->{$offender_address}->{VICTIMS}->{$victim_address};
			$incident_data = $RPT_CACHE->{incident}->{OFFENDERS}->{$offender_address}->{VICTIMS}->{$victim_address};

			# Check if there was an explict override set. This currently means
			# that the tag id in the conn data matches a tag id in an alarm of
			# interest.
			
			if( my $matched_tag =
				Bro::Log::Conn::containstag( $conn_struc,
					keys( %{$data_root->{WATCH_TAG_IDS}} ) ) )
			{
				delete( $data_root->{WATCH_TAG_IDS}->{$matched_tag} );
				print $temp_fh $$conn_line;
				++$incident_data->{CONN_COUNT};
			}
			# CONN_COUNT must be > 0.  This means that the tagged alarm has
			# been added and further conn data should be gathered.
			# Check if enough conn data has already been gathered for this incident
			elsif( $incident_data->{CONN_COUNT} > 0 and
				$incident_data->{CONN_COUNT} < $MAX_INCIDENT_CONN_LINES )
			{
				print $temp_fh $$conn_line;
				++$incident_data->{CONN_COUNT};
			}
			# Conn data can be out of order.  If the conn data containing a tag
			# id has not been encountered then start gathering data that's at
			# least at or after the first alarm time for an incident.
			elsif( $incident_data->{CONN_COUNT} < 1 and
				Bro::Log::Conn::timestamp( $conn_struc ) >= $incident_data->{BEGIN_TIMESTAMP} )
			{
				print $temp_fh $$conn_line;
				++$incident_data->{CONN_COUNT};
			}
		}
	}
	
	return( 1 );
}

sub reportableoffense
{
	my $sub_name = 'reportableoffense';
	
	my $alarm_struc = $_[0] || return( undef );
	my $ret_val = 0;
	
	if( reportableincident( $alarm_struc ) )
	{
		$ret_val = 1;
	}
	elsif( reportablescan( $alarm_struc ) )
	{
		$ret_val = 1;
	}
	
	return( $ret_val );
}

sub reportableincident
{
	my $sub_name = 'reportableincident';
	
	my $alarm_struc = $_[0] || return( undef );
	my $notice_type = Bro::Log::Alarm::notice_type( $alarm_struc );
	my $ret_val = 0;
	
	if( exists( $INCIDENT_EVENT_LIST->{$notice_type} ) )
	{
		if( exists( $INCIDENT_EVENT_LIST->{DEFAULT_IGNORE} ) )
		{
			$ret_val = 1;
		}
		else
		{
			$ret_val = 0;
		}
	}
	elsif( exists( $INCIDENT_EVENT_LIST->{DEFAULT_IGNORE} ) )
	{
		$ret_val = 0;
	}
	else
	{
		$ret_val = 1;
	}
	
	# If it is reportable make sure it is not classified as a scan
	if( $ret_val and reportablescan( $alarm_struc ) )
	{
		$ret_val = 0;
	}
	
	return( $ret_val );
}

sub setreportableincident
{
	my $sub_name = 'setreportableincident';
	my @incident_list = @_;
	
	# If called with one or more parameters then modify the list
	if( @incident_list > 0 )
	{
		foreach my $notice_type( @incident_list )
		{
			if( $notice_type eq 'DEFAULT_ALLOW' )
			{
				$INCIDENT_EVENT_LIST->{'DEFAULT_ALLOW'} = 1;
				delete( $INCIDENT_EVENT_LIST->{'DEFAULT_IGNORE'} );
			}
			elsif( $notice_type eq 'DEFAULT_IGNORE' )
			{
				$INCIDENT_EVENT_LIST->{'DEFAULT_IGNORE'} = 1;
				delete( $INCIDENT_EVENT_LIST->{'DEFAULT_ALLOW'} )
			}
			elsif( $notice_type =~ m/^\-([^[:space:]]+)$/ )
			{
				$notice_type = $1;
				delete( $INCIDENT_EVENT_LIST->{$notice_type} );
			}
			elsif( $notice_type =~ m/^\+?([^[:space:]]+)$/ )
			{
				$notice_type = $1;
				$INCIDENT_EVENT_LIST->{$notice_type} = 1;
			}
		}

		# Make sure that a default policy has been set
		if( ! ( exists( $INCIDENT_EVENT_LIST->{'DEFAULT_IGNORE'} ) or
			exists( $INCIDENT_EVENT_LIST->{'DEFAULT_ALLOW'} ) ) )
		{
			$INCIDENT_EVENT_LIST->{'DEFAULT_ALLOW'} = 1;
		}
	}
	
	# construct the current list contained in the incident event list.
	# The last element of the list will alway be the current default 
	# policy of DEFAULT_ALLOW or DEFAULT_IGNORE
	my %dupe_event_list = %{$INCIDENT_EVENT_LIST};
	my $default_policy;
	if( exists( $dupe_event_list{DEFAULT_ALLOW} ) )
	{
		$default_policy = 'DEFAULT_ALLOW';
	}
	else
	{
		$default_policy = 'DEFAULT_IGNORE';
	}
	delete( $dupe_event_list{$default_policy} );
	
	# Return the list of incident events and the default policy
	# that will be applied to the list.
	return( keys( %dupe_event_list ), $default_policy );
}

sub reportablescan
{
	my $sub_name = 'reportablescan';
	
	my $alarm_struc = $_[0] || return( undef );
	my $notice_type = Bro::Log::Alarm::notice_type( $alarm_struc );
	
	if( exists( $SCAN_EVENT_LIST->{$notice_type} ) )
	{
		return( 1 );
	}
	else
	{
		return( 0 );
	}
}

sub setreportablescan
{
	my $sub_name = 'setreportablescan';
	
	my @scan_list = @_;
	
	# If one or more args are passed then modify the list
	if( @scan_list > 0 )
	{
		foreach my $notice_type( @scan_list )
		{
			if( $notice_type =~ m/^\-([^[:space:]]+)$/ )
			{
				$notice_type = $1;
				delete( $SCAN_EVENT_LIST->{$notice_type} );
			}
			elsif( $notice_type =~ m/^\+?([^[:space:]]+)$/ )
			{
				$notice_type = $1;
				$SCAN_EVENT_LIST->{$notice_type} = 1;
			}
		}
	}
	
	# Return the list of notices types that are considered scans.
	return( keys( %{$SCAN_EVENT_LIST} ) );
}

sub tempincidentfile
{
	my $sub_name = 'tempincidentfile';
	
	my $arg = $_[0];
	
	if( $arg eq 'close' )
	{
		close( $RPT_CACHE->{incident}->{TEMP_FILE_HANDLE} );
		delete( $RPT_CACHE->{incident}->{TEMP_FILE_HANDLE} );
		return( 1 );
	}
	
	if( ! exists( $RPT_CACHE->{incident}->{TEMP_FILE_NAME} ) )
	{
		$RPT_CACHE->{incident}->{TEMP_FILE_NAME} = 
			tempfile( 'add', "incident_conn_data." );
		
		if( $DEBUG > 2 )
		{
			warn( "Created incident temp file " . $RPT_CACHE->{incident}->{TEMP_FILE_NAME} . "\n" );
		}
	}
	
	if( exists( $RPT_CACHE->{incident}->{TEMP_FILE_HANDLE} ) )
	{
		return( $RPT_CACHE->{incident}->{TEMP_FILE_HANDLE} );
	}
	else
	{
		if( open( INCTEMPOUT, ">>" .$RPT_CACHE->{incident}->{TEMP_FILE_NAME} ) )
		{
			$RPT_CACHE->{incident}->{TEMP_FILE_HANDLE} = \*INCTEMPOUT;
			return( $RPT_CACHE->{incident}->{TEMP_FILE_HANDLE} );
		}
		else
		{
			warn( __PACKAGE__ . "::$sub_name, Unable to open temp file " . $RPT_CACHE->{incident}->{TEMP_FILE_NAME} . " for writting\n" );
			return( undef );
		}
	}
}

sub incidentconndata
{
	my $sub_name = 'incidentconndata';
	
	my $offender = $_[0] || return( undef );
	my $victim = $_[1] || return( undef );
	my $start_time = $_[2] || -1;
	my $end_time = $_[3] || 9999999999;
	
	my @matching_lines;
	my %times;
	my $idx = 0;
	my @ret_strucs;
	
	if( ! $RPT_CACHE->{incident}->{TEMP_FILE_NAME} )
	{
		warn( "No incident temp file exists.  Unable to add connection data to incidents.\n" );
		return( undef );
	}
	
	if( open( INFILE, $RPT_CACHE->{incident}->{TEMP_FILE_NAME} ) )
	{
		while( defined( my $line = <INFILE> ) and $idx < $MAX_INCIDENT_CONN_LINES )
		{
			if( $line =~ m/$victim/ and $line =~ m/$offender/ )
			{
				my $conn_struc = Bro::Log::Conn::new( \$line );
				my( $conn_start, $conn_end ) = Bro::Log::Conn::range( $conn_struc );

				# Conn timestamps can be duplicates, check here for that case.
				if( exists( $times{$conn_start} ) )
				{
					push( @{$matching_lines[$times{$conn_start}]}, $conn_struc );
				}
				else
				{
					$times{$conn_start} = $idx;
					
					push( @{$matching_lines[$idx]}, $conn_struc );
					++$idx;
				}
			}
		}
	}
	else
	{
		warn( "Failed to open incident temp file " . $RPT_CACHE->{incident}->{TEMP_FILE_NAME} . " for reading.\n" );
	}
	
	close( INFILE );
	
	# Sort the lines in ascending order
	foreach my $key( sort( {$a <=> $b} keys( %times ) ) )
	{
		push( @ret_strucs, @{$matching_lines[$times{$key}]} );
	}
	
	return( @ret_strucs );
}


sub check_incident_struc
{
	foreach my $sus( keys( %{$RPT_CACHE->{incident}->{OFFENDERS}} ) )
	{
		if( ! $sus )
		{
			print "Suspect is undef\n";
			return( undef );
		}
		
		if( ! $RPT_CACHE->{incident}->{OFFENDERS}->{$sus} )
		{
			print "Incident data not defined\n";
			return( undef );
		}
		
		if( ! exists( $RPT_CACHE->{incident}->{OFFENDERS}->{$sus}->{VICTIMS} ) )
		{
			print "No data for VICTIMS\n";
			return( undef );
		}
		
		print "NEW OFFENDER: $sus\n";
		foreach my $vic( keys( %{$RPT_CACHE->{incident}->{OFFENDERS}->{$sus}->{VICTIMS}} ) )
		{
			if( ! $vic )
			{
				print "Victim is not defined\n";
				return( undef );
			}
			print "NEW VICTIM: $vic\n";
			
			if( ! $RPT_CACHE->{incident}->{OFFENDERS}->{$sus}->{VICTIMS}->{$vic} )
			{
				print "Victim data is not defined\n";
				return( undef );
			}
			
			foreach my $key( keys( %{$RPT_CACHE->{incident}->{OFFENDERS}->{$sus}->{VICTIMS}->{$vic}} ) )
			{
				print "KEY: $key\n";
			}
			
			foreach my $alarm( @{$RPT_CACHE->{incident}->{OFFENDERS}->{$sus}->{VICTIMS}->{$vic}->{ALARMS}} )
			{
				print "Message: ". Bro::Log::Alarm::message( $alarm ) ."\n";
			}
		}
		
		print "     END\n";
	}
}

sub availablereports
{
	my $sub_name = 'availablereports';
	
	my @ret_list = keys( %REPORT_MAP );
	
	return( @ret_list );
}

sub reportinputfunc
{
	my $sub_name = 'reportinputfunc';
	
	my $report_name = $_[0] || return( undef );
	
	if( exists( $REPORT_MAP{$report_name} ) )
	{
		return( $REPORT_MAP{$report_name}->{'input'} );
	}
	else
	{
		return( undef );
	}
}

sub reportoutputfunc
{
	my $sub_name = 'reportoutputfunc';
	
	my $report_name = $_[0] || return( undef );
	
	if( exists( $REPORT_MAP{$report_name} ) )
	{
		return( $REPORT_MAP{$report_name}->{'output'} );
	}
	else
	{
		return( undef );
	}
}

sub loadsignaturecode
{
	my $sub_name = 'loadsignaturecode';
	
	my @args = @_;
	my %match_sigs;
	my @file_list;
	
	if( @args > 0 )
	{
		# If a list of signatures to find is given then only those will be 
		  # stored otherwise all signatures will be stored.
		
		foreach my $sigid( @args )
		{
			$match_sigs{$sigid} = 1;
		}
	}
	
	if( ! ( @file_list = Bro::Signature::filelist() ) )
	{
		warn( __PACKAGE__ . "::$sub_name, Unable to retrieve a list of signature files\n" );
	}
	
	foreach my $file_name( @file_list )
	{
		foreach my $sig_obj( getrules( $file_name ) )
		{
			my $code_sigid = $sig_obj->sigid();
			if( !( %match_sigs ) or exists( $match_sigs{$code_sigid} ) )
			{
				$RPT_CACHE->{signaturecode}->{$code_sigid} = $sig_obj->output();
			}
		}
	}
}

sub signaturecode
{
	my $sub_name = 'signaturecode';
	
	my $sigid = $_[0] || return( undef );
	
	# Check on whether the signature block has been found and stored.
	if( $RPT_CACHE->{signaturecode}->{$sigid} )
	{
		return( $RPT_CACHE->{signaturecode}->{$sigid} );
	}
	else
	{
		return( '' );
	}
}


1;
