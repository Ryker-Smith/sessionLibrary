#!/usr/bin/perl
package simpleVars;
use strict;

require Exporter;
our @ISA = qw(Exporter);

###############
#our ($dbh); # master database handle
###############

our @EXPORT_OK= qw (
                    $variablesTable
                    &getValue &setValue
                   );
our %EXPORT_TAGS = (all => [@EXPORT_OK]);

use constant error=>0;
our $variablesTable='SessionManager.Variables';

sub getValue {
# Purpose:  Get 'variable' from current database
# Expects:  db handle, variable name
# Returns:  -
  my ($qry, $qh);
  my ($dbh, $key)=@_;
  $qry="SELECT varValue FROM $variablesTable WHERE varName LIKE ?";
  $qh=$$dbh->prepare($qry);
  $qh->execute($key);
  if (my $value=$qh->fetchrow()) {
    return $value;
  }
  else {
    return "Error";
  }
}

sub setValue {
# Purpose:  save 'variable' to current database
# Expects:  Handle to current db, name, value pair
# Returns:  -
  my ($qry, $qh);
  my $dbh=shift;
  my $varName=shift;
  my $varValue=shift;
  $qry="UPDATE $variablesTable SET varValue=? WHERE varName=?;";
  $qh=$$dbh->prepare($qry);
  my $result=$qh->execute($varValue, $varName);
  if ($result != 1) {
    return error;
  }
  my $key=$$dbh->{'mysql_insertid'};
  return $key;
}