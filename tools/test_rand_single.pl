#!/usr/bin/perl -w

$#ARGV>=1 or die "usage: test_rand_single.pl seed count [flags]";

($seed,$count,@f)=@ARGV;


if ($#f>=0) {
    $flags = join(" ", @f);
} else {
    $flags = "";
}

$ENV{PACKLAB_PASSWORD}="cs213";


if (system "tools/gen_rands $seed $count test.raw") {
    print "failed to generate test.raw\n";
    goto bad;
}
if (system "./pack $flags test.raw test.packed") {
    print "failed to pack test.raw into test.packed\n";
    goto bad;
}
if (system "./unpack test.packed test.unpacked") {
    print "failed to unpack test.packed into test.unpacked\n";
    goto bad;
}

if (system "diff test.unpacked test.raw") {
    print "test.unpacked is not the same as test.raw\n";
    goto bad;
}

print "test_rand_single.pl succeeded with seed $seed count $count and flags \"$flags\"\n";
exit 0;


 bad:
    print "test_rand_single.pl FAILED with seed $seed count $count and flags \"$flags\"\n";
    exit -1;
