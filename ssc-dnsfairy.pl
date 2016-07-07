#!/usr/bin/perl -w

use Net::SNMP;
use Net::IP;
use Class::CSV;
use Getopt::Std;
use XML::Dumper;
use strict;

my %opts;
getopt('hc', \%opts); # h is host, c is community

my $intoid = '1.3.6.1.2.1.31.1.1.1.1';
my $ipoid = '1.3.6.1.2.1.4.20.1.2';
my $sysname = '1.3.6.1.2.1.1.5.0';
my $hostname;
my $ifindexref = ([]);
my %iphash;
my %intnamehash;

my ($session, $error) = Net::SNMP->session(
                           -hostname      => $opts{'h'},
                           -port          => 161,
                           -version       => 2,
                           -community     => $opts{'c'},   # v1/v2c  
                        );

die $error if $error;

# Get the system name

my $result = $session->get_request(-varbindlist => [$sysname]);

die $error if $error;

# Sanitize hostname

foreach (values %$result)
        {
	s/^([^.]++).*/$1/; #Cut out only the hostname if there's a FQDN.
	s/\(\S*\)//gi;    #Kill garbage in parens, including parens
	s/\s/-/g;          #Kill whitespace
	$hostname=$_ . '.net.ssnc.global'; # Form hostname with new FQDN
        }

# Get Index Numbers of All interfaces with IP

$result = $session->get_table(-baseoid => $ipoid);

die $error if $error;

foreach (keys %$result)
        {
        my $indexnum = $$result{$_};
        push( @$ifindexref, "$intoid.$indexnum" );
        s/^.*\.(\d+\.\d+\.\d+\.\d+)$/$1/;                # Find IP embedded in the OID of the response
        $iphash{$indexnum}=$_;				# Then put it in the %iphash
        }

# Now match those Index Numbers with thier names

while (scalar @$ifindexref > 0) # Need to put a loop to prevent asking more than 10 OIDs per shot of the agent.
        {
        $result = $session->get_request(-varbindlist => [splice(@$ifindexref,0,10)]);

        die $error if $error;

        foreach (keys %$result)
                {
                $$result{$_} =~ s/[\s.\/]/-/g;
                my $intname = $$result{$_};
                my $name = $hostname;
                $name =~ s/^([^.]+)(\..*)?$/$1-$intname$2/;
                s/^.*\.(\d+)$/$1/;
                $intnamehash{$_}=$name;
                }
        }
# We're done with SNMP so let's kill the session object

$session->close;

# Build and spit out the CSV

my @csvfields=qw(ptrdname address ptrformat);
my $csv = Class::CSV->new(fields=>\@csvfields);
$csv->add_line($csv->fields);

#print pl2xml(\%iphash);
#print pl2xml(\%intnamehash);
foreach my $index (keys %iphash)
	{
	my $ip = new Net::IP($iphash{$index});
	$csv->add_line( {ptrdname=>$intnamehash{$index},
			address=>$iphash{$index},
			ptrformat=> $ip->reverse_ip});
	}

$csv->print;
