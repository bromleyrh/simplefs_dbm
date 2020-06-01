#!/usr/bin/env perl

#
# spec_to_h.pl
#

# FIXME: Length of output C string constants should be limited to 509 characters

use strict;
use warnings;

sub print_usage;
sub parse_cmdline;

sub char_at;
sub strlen;

sub process_line;

sub process_file;

sub print_usage {
    my ($stderr) = @_;

    my $str = "Usage: $0 FILE_NAME MACRO_NAME\n";

    if ($stderr) {
        warn($str);
    } else {
        print($str);
    }
}

sub parse_cmdline {
    if (@ARGV < 2) {
        print_usage(1);
        exit(1);
    }

    return ($ARGV[0], $ARGV[1]);
}

sub char_at {
    return substr($_[0], $_[1], 1);
}

sub strlen {
    use bytes;
    return length($_[0]);
}

sub process_line {
    my ($line) = @_;

    my $escapec = "\\";
    my $escaped = 0;
    my $in_quotes = 0;
    my $len = strlen($line);
    my $line_erased = 1;
    my $quotc = "\"";
    my $res = "";

    for (my $i = 0;; $i++) {
        if ($i == $len) {
            $line_erased = 0;
            last;
        }

        my $c = char_at($line, $i);

        if ($escaped) {
            $escaped = $line_erased = 0;
        } elsif ($in_quotes) {
            if (($c eq $quotc) and (not $escaped)) {
                $in_quotes = 0;
            } elsif ($c eq $escapec) {
                $escaped = 1;
            }
        } elsif ($c eq $escapec) {
            if ($i < $len - 1) {
                $c = char_at($line, ++$i);
            }
            $line_erased = 0;
        } elsif ($c eq $quotc) {
            $in_quotes = 1;
            $line_erased = 0;
        } else {
            last if ($c eq "#");
            $line_erased = 0 if (!($c =~ /\s/));
        }

        $res .= $c;
    }

    return ($res, $line_erased);
}

sub process_file {
    my ($filename, $macroname) = @_;

    open(my $f, "<", "$filename") or do {
        warn("Couldn't open $filename: $!\n");
        return -1;
    };

    print("#define _$macroname(text) #text\n",
          "\n",
          "#define $macroname _$macroname( \\\n");

    while () {
        my $ln = <$f>;
        last if (not defined($ln));

        my ($s, $line_erased) = process_line(substr($ln, 0, -1));
        if (!$line_erased) {
            my $lc = substr($s, -1);
            my $sep = (($lc eq "") or ($lc =~ /\s/)) ? "\\" : " \\";
            print("$s$sep\n");
        }
    }

    close($f);

    print(")\n");

    return 0;
}

(my $filename, my $macroname) = parse_cmdline();
(process_file($filename, $macroname) == 0) or exit(1);

# vi: set expandtab sw=4 ts=4:
