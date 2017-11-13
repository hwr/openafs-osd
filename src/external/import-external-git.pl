#!/usr/bin/perl

use strict;
use warnings;

use English;
use Getopt::Long;
use File::Basename;
use File::Temp;
use File::Path;
use IO::File;
use IO::Pipe;
use Pod::Usage;
use Cwd;

# Import an external git repository into the OpenAFS tree, taking the path
# to a local clone of that repository, a file containing a list of mappings
# between that repository and the location in the OpenAFS one, and optionally
# a commit-ish

my $help;
my $man;
my $externalDir;
my $nowhitespace;
my $result = GetOptions("help|?" => \$help,
			"nofixwhitespace" => \$nowhitespace,
			"man" => \$man,
			"externaldir=s" => \$externalDir);
		
pod2usage(1) if $help;
pod2usage(-existatus => 0, -verbose =>2) if $man;

my $module = shift;
my $clonePath = shift;
my $commitish = shift;

pod2usage(2) if !defined($module) || !defined($clonePath);

if (!$commitish) {
  $commitish = "HEAD";
}

# Use the PROGRAM_NAME to work out where we should be importing to.
if (!$externalDir) {
  $externalDir = dirname(Cwd::abs_path($PROGRAM_NAME));
}

# Read in our mapping file
my %mapping;
my $fh = IO::File->new("$externalDir/$module-files")
  or die "Couldn't open mapping file : $!\n";
while (<$fh>) {
  next if /^\s#/;
  if (/^(\S+)\s+(\S+)$/) {
    $mapping{$1} = $2;
  } elsif (/\w+/) {
    die "Unrecognised line in mapping file : $_\n";
  }
}
undef $fh;

# Read in our last-sha1 file
my $last;

$fh = IO::File->new("$externalDir/$module-last");
if ($fh) {
  $last = $fh->getline;
  chomp $last;
}
undef $fh;

my $author;
$fh = IO::File->new("$externalDir/$module-author");
if ($fh) {
  $author = $fh->getline;
  chomp $author;
}
undef $fh;

# Create the external directory, if it doesn't exist.
mkdir "$externalDir/$module" if (! -d "$externalDir/$module");

# Make ourselves a temporary directory
my $tempdir = File::Temp::tempdir(CLEANUP => 1);

# Write a list of all of the files that we're going to want out of the other
# repository in a format we can use with tar.
$fh = IO::File->new($tempdir."/filelist", "w")
  or die "Can't open temporary file list for writing\n";
foreach (sort keys(%mapping)) {
  $fh->print("source/".$_."\n");
}
undef $fh;

# Change directory to the root of the source repository
chdir $clonePath
  or die "Unable to change directory to $clonePath : $!\n";

# Figure out some better names for the commit object we're using
my $commitSha1 = `git rev-parse $commitish`;
my $commitDesc = `git describe $commitish`;
chomp $commitSha1;
chomp $commitDesc;

# If we know what our last import was, then get a list of all of the changes
# since that import
my $changes;
if ($last) {
  my $filelist = join(' ', sort keys(%mapping));
  $changes = `git shortlog $last..$commitish $filelist`;
}

# Populate our temporary directory with the originals of everything that was
# listed in the mapping file
system("git archive --format=tar --prefix=source/ $commitish".
       "  | tar -x -C $tempdir -T $tempdir/filelist") == 0
 or die "git archive and tar failed : $!\n";

# change our CWD to the module directory - git ls-files seems to require this
chdir "$externalDir/$module"
  or die "Unable to change directory to $externalDir/$module : $!\n";

# Now we're about to start fiddling with local state. Make a note of where we
# were.

# Use git stash to preserve whatever state there may be in the current
# working tree. Sadly git stash returns a 0 exit status if there are no
# local changes, so we need to check for local changes first.

my $stashed;
if (system("git diff-index --quiet --cached HEAD --ignore-submodules") != 0 ||
    system("git diff-files --quiet --ignore-submodules") != 0) {
  if (system("git stash") != 0) {
    die "git stash failed with : $!\n";
  }
  $stashed = 1;
}


eval {
  my @addedFiles;
  my @deletedFiles;

  # Use git-ls-files to get the list of currently committed files for the module
  my $lspipe = IO::Pipe->new();
  $lspipe->reader(qw(git ls-files));

  my %filesInTree;
  while(<$lspipe>) {
    chomp;
    $filesInTree{$_}++;
  }

  foreach my $source (sort keys(%mapping)) {
    if (-f "$tempdir/source/$source") {
      File::Path::make_path(File::Basename::dirname($mapping{$source}));
      if (!-f "$externalDir/$module/".$mapping{$source}) {
	 push @addedFiles, $mapping{$source};
      }
      system("cp $tempdir/source/$source ".
	     "   $externalDir/$module/".$mapping{$source}) == 0
         or die "Copy failed with $!\n";
      system("git add $externalDir/$module/".$mapping{$source}) == 0
         or die "git add failed with $!\n";
      delete $filesInTree{$mapping{$source}}
    } else {
      die "Couldn't find file $source in original tree\n";
    }
  }

  # Use git rm to delete everything that's committed that we don't have a
  # relacement for.
  foreach my $missing (keys(%filesInTree)) {
    system("git rm $missing") == 0
      or die "Couldn't git rm $missing : $!\n";
    push @deletedFiles, $missing;
  }

  if (system("git status") == 0) {
    my $fh=IO::File->new("$externalDir/$module-last", "w");
    $fh->print($commitSha1."\n");
    undef $fh;
    system("git add $externalDir/$module-last") == 0
       or die "Git add of last file failed with $!\n";

    $fh=IO::File->new("$tempdir/commit-msg", "w")
      or die "Unable to write commit message\n";
    $fh->print("Import of code from $module\n");
    $fh->print("\n");
    $fh->print("This commit updates the code imported from $module to\n");
    $fh->print("$commitSha1 ($commitDesc)\n");
    if ($changes) {
	$fh->print("\n");
	$fh->print("Upstream changes are:\n\n");
	$fh->print($changes);
    }
    if (@addedFiles) {
	$fh->print("\n");
	$fh->print("New files are:\n");
	$fh->print(join("\n", map { "\t".$_  } sort @addedFiles));
	$fh->print("\n");
    }
    if (@deletedFiles) {
	$fh->print("\n");
	$fh->print("Deleted files are:\n");
	$fh->print(join("\n", map { "\t".$_  } sort @deletedFiles));
	$fh->print("\n");
    }
    undef $fh;
    $author="--author '$author'" if ($author);
    system("git commit --no-verify -F $tempdir/commit-msg $author") == 0
      or die "Commit failed : $!\n";
    if ($nowhitespace) {
	print STDERR "WARNING: not fixing whitespace errors.\n";
    } else {
	system("git rebase --whitespace=fix HEAD^") == 0
	    or print STDERR "WARNING: Fixing whitespace errors failed.\n";
    }
    system("GIT_EDITOR=true git commit --amend") == 0
      or print STDERR "WARNING: Firing commit msg hooks failed.\n";
  }
};

my $code = 0;

if ($@) {
  print STDERR "Import failed with $@\n";
  print STDERR "Attempting to reset back to where we were ...\n";
  system("git reset --hard HEAD") == 0
    or die "Unable to reset, sorry. You'll need to pick up the pieces\n";
  $code = 1;
} 

if ($stashed) {
  system("git stash pop") == 0
    or die "git stash pop failed with : $!\n";
}

exit $code;

__END__

=head1 NAME

import-external-git - Import bits of an external git repo to OpenAFS

=head1 SYNOPSIS

import-external-git [options] <module> <repository> [<commitish>]

  Options
    --help		brief help message
    --man		full documentation
    --externalDir	exact path to import into
    --nofixwhitespace   don't apply whitespace fixes

=head1 DESCRIPTION

import-external-git imports selected files from an external git repository
into the OpenAFS src/external tree. For a given <module> it assumes that
src/external/<module>-files already exists, and contains a space separated
list of source and destination file names. <repository> should point to a
local clone of the external project's git repository, and <commitish> points
to an object within that tree. If <commitish> isn't specified, the current
branch HEAD of that repository is used.

=cut
