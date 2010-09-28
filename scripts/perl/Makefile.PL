require 5.006_001;
use ExtUtils::MakeMaker;
use Cwd;
use strict;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

my @args = @ARGV;
my @cleaned_args;
my $scripts_dir = './script';
my $scripts_list;
my $brohome = '';
my $broconfig = '';
my %extra_args = ( 'BROHOME' => \$brohome, 'BROCONFIG' => \$broconfig, );

# Look for any extra args that are not recognized by MakeMaker.  Use and
# then omit from the array of the final args to pass to MakeMaker.
foreach my $arg( @args )
{
	$arg =~ m/^(.+)=(.+)/;
	my $key = $1;
	my $val = $2;
	if( exists( $extra_args{$key} ) )
	{
		${$extra_args{$key}} = $val;
	}
	else
	{
		push( @cleaned_args, $arg );
	}
}

# If any extra args that are not recognized by MakeMaker existed they are removed
# by now.
@_ = @cleaned_args;
@ARGV = @cleaned_args;

if( ! $brohome )
{
	if( exists( $ENV{BROHOME} ) )
	{
		$brohome = $ENV{BROHOME};
	}
	else
	{
		$brohome = '/usr/local/bro';
	}
}

if( ! $broconfig )
{
	$broconfig = "$brohome/etc/bro.cfg";
}



check_prereqs();

$scripts_list = get_exe_list();

foreach my $file( @{$scripts_list} )
{
	setbroconfig( $broconfig, $file );
}

WriteMakefile(
	'NAME'			=> 'Bro',
	'DISTNAME'		=> 'Bro-Utilities',
	'VERSION_FROM'		=> 'lib/Bro/Config.pm', # finds $VERSION
	'PREREQ_PM'		=> { 'Config::General' => 2.27,
					'Time::Local' => 0,
					'Getopt::Long' => 0,
					'Socket' => 0,
					},
	'EXE_FILES'		=> $scripts_list,
	'dist'		=> {
		'COMPRESS'	=> 'gzip',
		'SUFFIX'		=> 'gz'
	},
	($] >= 5.005 ?    ## Add these new keywords supported since 5.005
	('AUTHOR'		=> 'Roger Winslow <rwinslow@lbl.gov>') : ()),
);


sub chk_version
{
	no strict qw( refs vars );
	my($pkg,$wanted,$msg) = @_;

	local($|) = 1;
	print "Checking for $pkg...";

	eval { my $p; ($p = $pkg . ".pm") =~ s#::#/#g; require $p; };

	print ${"${pkg}::VERSION"} ? "found v" . ${"${pkg}::VERSION"}
						   : "not found";
	print "\n";
	my $vnum = ${"${pkg}::VERSION"} || 0;

	if( $vnum >= $wanted )
	{
		print "$pkg is installed\n";
		return( 1 );
	}
	else
	{
		return();
	}
	
	use strict;
}

sub check_prereqs
{	
	my $failed_prereq = 0;
	
	# Require perl version 5.6.1 or greater
	eval { require 5.006_001; };
	if( $@ )
	{
		die( "The minimum version of perl required is 5.6.1 (5.006_001).  Please use a different perl binary to install this package.\n" );
	}
	
	if( chk_version( 'Config::General' => '2.27' ) )
	{
		# do nothing
	}
	else
	{
		my $orig_dir = cwd();
		
		# Bypass the user prompt for this version
		# my $confer = prompt( "Config::General is not installed. Would you like to install it now?",
		#		'yes' );
		
		my $confer = 'y';
		if( $confer =~ m/yes|y/i )
		{
			chdir 'ext';
			unpack_archive( 'Config-General-2.27.tar.gz' );
			chdir 'Config-General-2.27';
			print "Installing Config-General-2.27.\n";
			sleep( 1 );
			do 'Makefile.PL';
			if( system( "make; make install" ) == 0 )
			{
				print "\n ........... done\n";
			}
			else
			{
				warn( "Failed to install perl package Config-General-2.27.\n" );
			}
			
			chdir "$orig_dir";
		}
	}
	
	if( $failed_prereq )
	{
		warn( "Failed one or more prerequisite test, unable to continue.\n" );
		exit( 1 );
	}

	print "\n";
}

sub unpack_archive
{
	my $_archive = shift || return( undef );
	
	system( "gzip -d < $_archive | tar xf -" );
}

sub get_exe_list
{
	my @ret_list;
	
	if( ! opendir( DIR, $scripts_dir ) )
	{
		warn( "Failed to open the scripts directory at $scripts_dir. Unable to continue.\n" );
		exit( 1 );
	}
	
	while( my $file = readdir( DIR ) )
	{
		if( $file !~ m/^\./ and $file !~ m/^makefile.*/i and
			-f "$scripts_dir/$file" )
		{
			push( @ret_list, "$scripts_dir/$file" );
		}
	}
	closedir( DIR );
	
	return( \@ret_list );
}

sub setbroconfig
{
	my $sub_name = 'setbroconfig';
	
	my $_broconfig = shift || return( undef );
	my $_file = shift || return( undef );
	
	if( ! open( INFILE, $_file ) )
	{
		warn( "$sub_name, Failed to open file $_file for reading.\n" );
		return( undef );
	}
	
	if( ! open( OUTFILE, ">$_file.in" ) )
	{
		warn( "$sub_name, Failed to open file $_file.in for writing.\n" );
		return( undef );
	}
	
	while( defined( my $line = <INFILE> ) )
	{
		$line =~ s/^([[:space:]]*\$DEFAULT_BRO_CONFIG_FILE[[:space:]]*=[[:space:]]*).+(\;.*)$/$1\'$_broconfig\'$2/;
        $line =~ s/\$DEFAULT_BRO_HOME/$brohome/;
		print OUTFILE $line;
	}
	
	close( OUTFILE );
	close( INFILE );
	
	system( "mv -f $_file.in $_file" );
	
	return( 1 );
}

