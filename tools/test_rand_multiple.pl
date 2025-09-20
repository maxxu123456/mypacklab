#!/usr/bin/perl -w

@flagcombos = (
    # raw ones
    "",
    "-c",
    "-e",
    "-k",
    "-c -e",
    "-c -k",
    "-e -k",
    "-c -e -k",
    # floating point 2 stream
    "-f",
    "-f -c",
    "-f -e",
    "-f -k",
    "-f -c -e",
    "-f -c -k",
    "-f -e -k",
    "-f -c -e -k",
    # extra credit floating point 3 stream
    "-g",
    "-g -c",
    "-g -e",
    "-g -k",
    "-g -c -e",
    "-g -c -k",
    "-g -e -k",
    "-g -c -e -k"
    );



$#ARGV==2 or die "usage: test_rand_mutiple.pl metaseed numtests countmin:countmax\nSee code for how to select flag combinations\n";

($metaseed,$numtests,$cr)=@ARGV;

if ($cr=~/(\d+)\:(\d+)/) {
    ($crmin,$crmax) = ($1,$2);
} else {
    die "can't parse count range $cr\n";
}

$ENV{PACKLAB_PASSWORD} = "cs213";

srand($metaseed);

open(LOG,">test.log") or die "cannot open log file\n";

for ($i=0;$i<$numtests;$i++) {
    $seed=$metaseed+$i;
    $count = $crmin+int(rand($crmax-$crmin+1));
    foreach $f (@flagcombos) {
	if (system "tools/test_rand_single.pl $seed $count $f") {
	    print LOG "BAD\ttest_rand_single.pl\t$seed\t$count\t$f\n";
	} else {
	    print LOG "good\ttest_rand_single.pl\t$seed\t$count\t$f\n";
	}
    }
}

close(LOG);

exit 0;

