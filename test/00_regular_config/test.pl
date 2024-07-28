#!/usr/bin/perl

# test.pl: small script to test mod_evasive's effectiveness
# - requires https virtualhosts a.site and b.site to be setup, each with their own mod_evasive config

#use IO::Socket;
use IO::Socket::SSL;
use strict;

sub request {
  my($address,$uri,$i) = @_;
  my($response);
  my($SOCKET) = new IO::Socket::INET( Proto   => "tcp",
                                      PeerAddr=> "127.0.0.1:1980");
#  my($SOCKET) = new IO::Socket::SSL( Proto   => "tcp",
#                                     PeerAddr=> "127.0.0.1:443");
  if (! defined $SOCKET) { die $!; }
  print $SOCKET "GET $uri?$i HTTP/1.1\r\n";
  print $SOCKET "Host: $address\r\n\r\n";
  $response = <$SOCKET>;
	chomp $response;
  print "$i - $address: $response\n";
  close($SOCKET);
}

for(0..900) {
	request "a.site", "/j_spring_security_check", $_;
}
for(0..50) {
	request "b.site", "/", $_;
}
for(0..100) {
	request "a.site", "/whitelisted-uri", $_;
}
print "done.\n"
