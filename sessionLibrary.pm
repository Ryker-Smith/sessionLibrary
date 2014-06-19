#!/usr/bin/perl
package sessionLibrary;
use strict;
use warnings;
use Date::Calc qw(Today Localtime Mktime Add_Delta_DHMS Today_and_Now Date_to_Text);
use String::Random;
use CGI;
use CGI::Cookie;

# DATE:   20140611  :DATE
# Program:  Package of session/authentication handling routines
# Object: Facilitate re-usability of code to authenticate user, return a sessionCode
#         (aka token) which can subsequently be used without any further transfer of
#         logon credentials.
#
# Author: faROE
# Date: Feb/2014
# Notes:
# Used on:  saveNotice for treeBeard/tv, admin login for clypic/hai
# Sources: http://www.w3schools.com/js/js_cookies.asp
# enable export of my bits
require Exporter;
our @ISA = qw(Exporter);

###############
our ($dbh); # master database handle
###############

our @EXPORT_OK= qw (
                    $dbh 
                    &sessionNew &sessionDelete &sessionUpdate &sessionExists &sessionValid
                    &showSessionLogIn &showSessionEmbeddedLogIn &sessionUser
                    &sessionAuthenticate &sessionSanityFail
                    &sessionFlagOn $sessionLogOut &sessionEnd 
                    &sessionTimeoutWatcher &sessionLog
                    &sessionCookieGet &sessionCookieSet &sessionCookieExpiry
                    sessionNull
                    $sessionLogIn $sessionVersion $sessionTable $sessionTimeOutDuration
                    $sessionUsers $sessionLog &sessionCleanUp $sessionJSON $sessionFormat
                    $webAppName
                    );
our %EXPORT_TAGS = (all => [@EXPORT_OK]);

use constant error=>0;
use constant maxFails=>10; # count
use constant defaultTimeOutDuration=>3600; # seconds
use constant sessionCookieName=>'sessionId_';
use constant sessionNull=>"-";

# codes - take care of overlap possibility
our $sessionLogIn=701;
our $sessionLogOut=702;
our $sessionJSON=703;

our $sessionVersion="0.1";
our $sessionFormat="ncccnccc";
our $sessionTable="SessionManager.Sessions";
our $sessionUsers="SessionManager.Users";
our $sessionLog="SessionManager.Logging";
our $sessionTimeOutDuration=defaultTimeOutDuration;

my $cgi= new CGI;
my $remoteIP4=$cgi->remote_addr();
my $homeIP4='46.7.199.1';
our $webAppName="DEFAULT";

sub sessionNew {
# Purpose:  generate (unique) id number
# Expects:  userName
# Returns:  sessionId
  my $userName=shift;
  my ($qry, $qh);
  my $num = new String::Random;
  my $sessionId=$num->randpattern($sessionFormat);
  # now test if session num is unique, keep tarck of
  # failed attempts an unique
  my $failCount=0;
  # test for code already-exists
  while ( (sessionExists($sessionId)) && ($failCount<=maxFails) ) {
    $sessionId=$num->randpattern($sessionFormat);
    # add one to fail tester
    $failCount++;
  }
  # should be OK when we get here
  # but I may be after damaging atomicity
  my $timestamp=unixTime();
  $qry="INSERT INTO $sessionTable (sessionId, sessionStart, sessionLast, userName, sessionIP4, sessionApplication) VALUES (?, ?, ?, ?, ?, ?);";
  $qh=$dbh->prepare($qry);
  my $cgi= new CGI;
  my $remote=$cgi->remote_addr();
  my $resultCode=$qh->execute($sessionId, $timestamp, $timestamp, $userName, $remote, $webAppName);
  # check the result
  if ($resultCode == 1) {
    return $sessionId;
  }
  else {
    return error;
  }
} # sessionNew

sub sessionDelete {
# Purpose:  delete sessionId id number
# Expects:  sessionId
# Returns:  resultCode
  my ($qry, $qh);
  my $sessionId=shift;
  $qry ="DELETE FROM $sessionTable WHERE sessionId LIKE ?;";
  $qh=$dbh->prepare($qry);
  $qh->execute($sessionId);
} # sessionDelete

sub sessionUpdate {
# Purpose:  Update sessionId timestamp
# Expects:  sessionId
# Returns:  result of update
  my ($qry, $qh);
  my $sessionId=shift;
  my $time=unixTime();
  $qry ="UPDATE $sessionTable SET sessionLast=? WHERE sessionId LIKE ?;";
  $qh=$dbh->prepare($qry);
  my $resultCode=$qh->execute($time, $sessionId);
  return $resultCode;
}

sub unixTime {
# Purpose:  generate unixTime integer
# Expects:  -
# Returns:  int unixTime
  my ($year,$month,$day, $hour,$min,$sec, $doy,$dow,$dst)=Localtime();
  my $time=Mktime($year,$month,$day, $hour,$min,$sec);
  return $time;
}

sub showSessionLogIn {
# Purpose:  standardised login
# Expects:  -
# Returns:  -
  # first get url of submit routine
  my $action=shift;
  my $style=shift;
  print <<sessionLogIn0;
  <!DOCTYPE html>
  <html>
  <head>
  <title>Log In</title>
  <link rel="stylesheet" type="text/css" href="$style" media="all"/>
  <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
  <!-- remove this later-->
  <style>
    #login {
      top: 0px;
      width: 200px;
      margin-left: auto;
      margin-right: auto;
    }
    red{
      color: red;
    }
    blue{
      color: blue;
    }
  </style>
  <script type="text/javascript">
  
  var myHost="https://treebeard.ie";
  var myLoginScriptUrl=myHost+"/yearPlanner";
  var errorMessage="<small><center><red>please provide your login details</red></center></small>";
  var failedLogin="<small><center><red>that's not right</red></center></small>";
  var pageTurning="<small><center><blue>turning page...</blue></center></small>";
  var loginAdvice="<small><center>Login:</center></small>";
  var checkingAdvice="<small><center><blue>checking that...</blue></center></small>";
  var error=0; // to match back-end value
  // why this next, when above also???
  var targetUrl="https://treebeard.ie/yearPlanner/";
  
  function startUp () {
    /*
      Purpose:  Set up the environment, page, etc
      Expects:  -
      Returns:  -
    */
    document.getElementById('feedback').innerHTML=loginAdvice;
    document.getElementById('user').value='';
    document.getElementById('pass').value='';

    document.getElementById('user').focus();
  }
  
  function authoriseMe () {
    /*
      Purpose:  Pass user credentials to authoriser back-end
      Expects:  -
      Returns:  -
    */
    var serverResponse;
    var myLoginScript=myLoginScriptUrl;
    // first get user details
    var user=document.getElementById('user').value;
    var pass=document.getElementById('pass').value;
    // enforce non-blank passwords as well user
    if (user == "" || pass =="") {
      document.getElementById('feedback').innerHTML=errorMessage;
      exit;
    }
    else if (document.getElementById('feedback').innerHTML == errorMessage) {
      document.getElementById('feedback').innerHTML=loginAdvice;
    }
    document.getElementById('feedback').innerHTML=checkingAdvice;
    // prepare to send to server
    var sessionRequest= new XMLHttpRequest();
    // prepare synchronous request
    // NB temporary bodge in use here: NB
    myLoginScript=myLoginScript+"?user="+user+"&pass="+pass+"&action=$sessionJSON";
    sessionRequest.open("GET", myLoginScript, false);
    sessionRequest.send();
    if (sessionRequest.status == 200) {
      serverResponse=JSON.parse(sessionRequest.responseText);
      if (serverResponse.status == "OK") {
        document.getElementById('feedback').innerHTML=pageTurning;
        targetUrl=targetUrl+"?sessionId="+serverResponse.sessionId;
        window.location.replace(targetUrl);
      }
      else {
        // login fail
        document.getElementById('feedback').innerHTML=failedLogin;
      }
    }
    else {
      // do what here? explode?
    }
  }
  </script>
  </head>
  <body onload="startUp()">
  <div id="login">
  <form method="POST" action="$action" id="submitForm" onsubmit="authoriseMe();">
  
  </script>
  <input type="hidden" name="action" id="action" value="$sessionLogIn">
  <table>
  <tr><td id="feedback" colspan="2" style="width: 100%; border-bottom: 1px solid black;"></td></tr>
  <tr><td>User:</td><td><input type="text" name="user" id="user"></td></tr>
  <tr><td>Pass:</td><td><input type="password" name="pass" id="pass"></td></tr>
  <tr><td colspan="2" style="border-top: 1px solid black;">
  <center><input type="button" value="Log In" onclick="authoriseMe();">
  <input style="display: none;" type="submit" value="I'm an invisible button!"></center></td></tr>
  </table>
  </form>
  </div>
  </body>
  </html>
sessionLogIn0
}

sub showSessionEmbeddedLogIn {
# Purpose:  standardised login
# Expects:  -
# Returns:  -
  # first get url of submit routine
  my ($action, $host, $appFullPath, $targetUrl, $domain)=@_;
  my $sessionCookieName=sessionCookieName . $domain;
  my $expiryTime=sessionCookieExpiry();
  open LOG, "> /var/www/treeBeard/html/yearPlanner/yearPlanner.log";
  print LOG "[$action][$host][$appFullPath][$targetUrl][$domain]\n";
  print <<sessionEmbeddedLogIn0;
  <style>
    #login {
      top: 0px;
      width: 200px;
      margin-left: auto;
      margin-right: auto;
    }
    red{
      color: red;
    }
    blue{
      color: blue;
    }
  </style>
  <script type="text/javascript">
  
  var myHost='$host';
  var myLoginScriptUrl='$appFullPath';
  var errorMessage="<small><center><red>please provide your login details</red></center></small>";
  var failedLogin="<small><center><red>that's not right</red></center></small>";
  var pageTurning="<small><center><blue>turning page...</blue></center></small>";
  var loginAdvice="<small><center>Login:</center></small>";
  var checkingAdvice="<small><center><blue>checking that...</blue></center></small>";
  var error=0; // to match back-end value
  // why this next, when above also???
  var targetUrl='$targetUrl';
  
  function authoriseMe () {
    /*
      Purpose:  Pass user credentials to authoriser back-end
      Expects:  -
      Returns:  -
    */
    var serverResponse;
    var myLoginScript=myLoginScriptUrl;
    // first get user details
    var user=document.getElementById('user').value;
    var pass=document.getElementById('pass').value;
    // enforce non-blank passwords as well user
    if (user == "" || pass =="") {
      document.getElementById('feedback').innerHTML=errorMessage;
      exit;
    }
    else if (document.getElementById('feedback').innerHTML == errorMessage) {
      document.getElementById('feedback').innerHTML=loginAdvice;
    }
    document.getElementById('feedback').innerHTML=checkingAdvice;
    // prepare to send to server
    var sessionRequest= new XMLHttpRequest();
    // prepare synchronous request
    // NB temporary bodge in use here: NB
    myLoginScript=myLoginScript+"?user="+user+"&pass="+pass+"&action=$sessionJSON";
    sessionRequest.open("GET", myLoginScript, false);
    sessionRequest.send();
    if (sessionRequest.status == 200) {
      serverResponse=JSON.parse(sessionRequest.responseText);
      if (serverResponse.status == "OK") {
        document.getElementById('feedback').innerHTML=pageTurning;
        // need to add cookie expiry
        document.cookie="$sessionCookieName="+serverResponse.sessionId + "; expires=$expiryTime;";
        targetUrl=targetUrl+"?sessionId="+serverResponse.sessionId;
        window.location.replace(targetUrl);
      }
      else {
        // login fail
        document.getElementById('feedback').innerHTML=failedLogin;
      }
    }
    else {
      // do what here? explode?
    }
  }
  </script>
  <div id="login">
  <form method="POST" action="$action" id="submitForm" onsubmit="authoriseMe();">
  <input type="hidden" name="action" id="action" value="$sessionLogIn">
  <table>
  <tr><td id="feedback" colspan="2" style="width: 100%; border-bottom: 1px solid black;"><small><center>Login:</center></small></td></tr>
  <tr><td>User:</td><td><input type="text" name="user" id="user"></td></tr>
  <tr><td>Pass:</td><td><input type="password" name="pass" id="pass"></td></tr>
  <tr><td colspan="2" style="border-top: 1px solid black;">
  <center><input type="button" value="Log In" onclick="authoriseMe();">
  <input style="display: none;" type="submit" value="I'm an invisible button!"></center></td></tr>
  </table>
  </form>
  </div>
sessionEmbeddedLogIn0
}

sub sessionAuthenticate {
# Purpose:  verify user/pass pair
# Expects:  user, pass
# Returns:  sessionId, or error
  my ($qry, $qh);
  # first get params
  my $sessionId;
  my $user=shift;
  my $pass=shift;
  if (sessionUserRestrictions($user)==1) {
    #???
  }
  $qry="SELECT COUNT(*) FROM $sessionUsers WHERE userName=? AND userSecret=?;";
  $qh=$dbh->prepare($qry);
  $qh->execute($user, $pass);
  my $count=$qh->fetchrow();  
  if ($count == 1) {
    $sessionId=sessionNew($user);
    sessionFlagOn($sessionId);
    return $sessionId;
  }
  else {
    return error;
  }
}

sub sessionEnd {
# Purpose:  disconnect session from DB
# Expects:  sessionId
# Returns:  -
  my $sessionId=shift;
  # there's probably no good reason for dropping
  # the flag before deleting.....
  sessionFlagOff($sessionId);
  sessionDelete($sessionId);
}

sub sessionExists {
# Purpose:  check for code existance in DB
# Expects:  sessionId
# Returns:  1 - exists, const error it doesn't
  my ($qry, $qh);
  my $sessionId=shift;
  if ($remoteIP4 eq $homeIP4) { return 1; }
  if (sessionSanityFail($sessionId)==1) {
    return error;
  }
  # just get a count of the sessionId
  $qry="SELECT Count(*) FROM $sessionTable WHERE sessionId LIKE ?;";
  $qh=$dbh->prepare($qry);
  $qh->execute($sessionId);
  my $count=$qh->fetchrow();
  # make sure return values meet guide above
  return $count;
  if ($count != 1) {
    return error;
  }
  else {
    return 1;
  }
} #

sub sessionValid {
# Purpose:  Determine is sessionId is valid, unexpired
# Expects:  sessionId
# Returns:  1, valid const error if invalid
#
  my ($qry, $qh);
  my $sessionId=shift;
  if ($remoteIP4 eq $homeIP4) { return 1; }
  if (  (sessionSanityFail($sessionId)==1) ||
        (sessionExists($sessionId) == error)  ) {
    return error;
  }
  # get min last time
  my $time=unixTime();
  $time -= defaultTimeOutDuration;
  # get time of last interaction
  $qry="SELECT sessionLast FROM $sessionTable WHERE sessionId LIKE ? AND sessionActive='1';";
  $qh=$dbh->prepare($qry);
  $qh->execute($sessionId);
  my $sessionLast=$qh->fetchrow();
  # make sure not timed out
  if ($sessionLast < $time) {
    return error;
  }
  else {
    return 1;
  }
} #

sub sessionCookieExpiry {
  my ($year,$month,$day, $hour,$min,$sec) = Add_Delta_DHMS(
                     Today_and_Now(),
                     0,0,0,$sessionTimeOutDuration );
  my $strDate = Date_to_Text($year,$month,$day) . " $hour:$min:$sec ";
  return $strDate;
}

sub sessionCookieSet {
# set a cookie on the remote puter with sessionID
#
# NOTE: Better to set cookie from browser using js
#
# Purpose:  set cookie to hold sessionID
# Expects:  domain string
#           sessionId
# Returns:  -
# 
  my $domain=shift;
  my $sessionId=shift;
  #print "<h1>[$domain][$sessionId]</h1>\n";
  my $expiryTime='+' . $sessionTimeOutDuration . 's'; #default value, must give option to change this
  # prepare the cookie
  my $cookie = CGI::Cookie->new(-name => sessionCookieName . $domain,
                                -value => $sessionId,
                                -expires => $expiryTime); # expire in?
  # send it
  #print "<h1>$cookie</h1>\n";
  $cookie->bake();
}

sub sessionCookieGet {
# Purpose:  Is there a sessionId cookie
# Expects:  domain string
# Returns:  1/0 present/not present - ALSO sets $cookiesOK global var
# most basic test, is there a permissions cookie?
  my %cookies = CGI::Cookie->fetch;
  my $domain=shift;
  my $cookieName=sessionCookieName . $domain;
  my ($sessionCookie);
  # first test if defined to avoid crash
  if (defined $cookies{$cookieName}) {
    # sessionId now in sessionCookie
    $sessionCookie = $cookies{$cookieName}->value;
    # check session not expired
    if (sessionValid($sessionCookie) == 1) {
      # Still active, update the session timer on the server
      sessionUpdate($sessionCookie);
      # return sessionId
      return $sessionCookie;
    }
  }
  # value not set, notify error
  return error;
}

sub sessionCookieUpdate {
}

sub sessionSanityFail {
# Purpose:  basic sanity check on sessionId
# Expects:  sessionId
# Returns:  ?fails: 0, valid const error invalid?
  my $sessionId=shift;
  if (($sessionId eq "") || ($sessionId eq "0")  ||
      (length($sessionId) != length ($sessionFormat))) {
    # testing for positive presence of error
    return 1;
  }
  else {
    return 0;
  }
}

sub sessionUserRestrictions {
# Purpose:  test for special handling for this user
# Expects:  user
# Returns:  ?fails: 0, valid const error invalid?
  my $user=shift;
  # to follow...
  return 0;
}

sub userExists {
# Purpose:  simple existance test for user
# Expects:  user
# Returns:  ?fails: 0, valid const error invalid?
# Notes:    consider security implications of this routine
  my $user=shift;
  # to follow...
  return 0;
}

sub sessionFlagOn {
# Purpose:  set flag ON user session
# Expects:  sessionId
# Returns:  -
  my ($qry, $qh);
  my $sessionId=shift;
  $qry="UPDATE $sessionTable SET sessionActive='1' WHERE sessionId LIKE ?;";
  $qh=$dbh->prepare($qry);
  $qh->execute($sessionId);
}

sub sessionFlagOff {
# Purpose:  set flag OFF user session
# Expects:  sessionId
# Returns:  -
  my ($qry, $qh);
  my $sessionId=shift;
  $qry="UPDATE $sessionTable SET sessionActive='0' WHERE sessionId LIKE ?;";
  $qh=$dbh->prepare($qry);
  $qh->execute($sessionId);
}

sub sessionCleanUp {
# Purpose:  remove expired sessions from db
# Expects:  
# Returns:  

  # to follow...
#  getS
  return 1;
}

sub sessionTimeoutWatcher {
  my $sessionId=shift;
  my $timeOut=defaultTimeOutDuration;
  my $html=<<ENDOFtimeoutwatcher;
  <script type="text/javascript">
   var remainingSeconds=$timeOut;
   var url = "/announce?action=$sessionLogOut&sessionId=$sessionId";
   var tid;

   function timeoutWatcher() {
      remainingSeconds--
      if (remainingSeconds>0) {
        tid=setTimeout("timeoutWatcher()", 1*1000);
      }
      else {
        window.defaultStatus="Session has timed-out";
        window.location.replace(url);
        clearTimeout(tid);
      }
   }

   timeoutWatcher();
</script>
ENDOFtimeoutwatcher
  return $html;
}

sub sessionLog {
# Purpose:  log string to DB
# Expects:  sessionId, action (cgi parameter)
# Returns:  
  my $sessionId=shift;
  my ($qry, $qh);
  if ($sessionId eq "") {
    $sessionId=sessionNull;
  }
  my $action=shift;
  my $msg=shift;
  if (defined $msg) {
    $action=$action." -> ".$msg;
  }
  my $user=sessionUser($sessionId);
  $qry="INSERT INTO $sessionLog (logUser, logEvent, logIP, logApplication, sessionId) VALUES (?, ?, ?, ?, ?);";
  $qh=$dbh->prepare($qry);
  my $resultCode=$qh->execute($user, $action, $remoteIP4, $webAppName, $sessionId);
  # no need to check the result
  return $resultCode;
}

sub sessionUser {
# Purpose:  log string to DB
# Expects:  sessionId, action (cgi parameter)
# Returns:  
  my ($qry, $qh);
  my $sessionId=shift;
  $qry="SELECT userName FROM $sessionTable WHERE sessionId=?;";
  $qh=$dbh->prepare($qry);
  $qh->execute($sessionId);
  my $user=$qh->fetchrow();
  if (!defined $user) {
    $user=sessionNull;
  }
  return $user;
}

=SKIP
create table `Sessions` (`sessionId` char(16) primary key,`sessionTime` timestamp default 'CURRENT_TIMESTAMP',`sessionStart` bigint(20),`sessionLast` bigint(20),`sessionIP4` char(16),`sessionActive` char(1),`userName` char(64))

create table `Sessions` (`sessionId` char(16) primary key,`sessionTime` timestamp default NOW(),`sessionStart` bigint(20),`sessionLast` bigint(20),`sessionIP4` char(16),`sessionActive` char(1),`userName` char(64));

=SKIP