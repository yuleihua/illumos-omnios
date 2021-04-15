#!@TOOLS_PYTHON@
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License version 2
#  as published by the Free Software Foundation.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#

#
# Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2008, 2012 Richard Lowe
# Copyright 2019 Garrett D'Amore <garrett@damore.org>
# Copyright (c) 2015, 2016 by Delphix. All rights reserved.
# Copyright 2016 Nexenta Systems, Inc.
# Copyright (c) 2019, Joyent, Inc.
# Copyright 2021 OmniOS Community Edition (OmniOSce) Association.
#

from __future__ import print_function

import getopt
import io
import os
import re
import subprocess
import sys
import tempfile

if sys.version_info[0] < 3:
    from cStringIO import StringIO
else:
    from io import StringIO

#
# Adjust the load path based on our location and the version of python into
# which it is being loaded.  This assumes the normal onbld directory
# structure, where we are in bin/ and the modules are in
# lib/python(version)?/onbld/Scm/.  If that changes so too must this.
#
sys.path.insert(1, os.path.join(os.path.dirname(__file__), "..", "lib",
                                "python%d.%d" % sys.version_info[:2]))

#
# Add the relative path to usr/src/tools to the load path, such that when run
# from the source tree we use the modules also within the source tree.
#
sys.path.insert(2, os.path.join(os.path.dirname(__file__), ".."))

from onbld.Scm import Ignore
from onbld.Checks import Comments, Copyright, CStyle, HdrChk, WsCheck
from onbld.Checks import JStyle, Keywords, ManLint, Mapfile, SpellCheck
from onbld.Checks import ShellLint

class GitError(Exception):
    pass

def git(command):
    """Run a command and return a stream containing its stdout (and write its
    stderr to its stdout)"""

    if type(command) != list:
        command = command.split()

    command = ["git"] + command

    try:
        tmpfile = tempfile.TemporaryFile(prefix="git-nits", mode="w+b")
    except EnvironmentError as e:
        raise GitError("Could not create temporary file: %s\n" % e)

    try:
        p = subprocess.Popen(command,
                             stdout=tmpfile,
                             stderr=subprocess.PIPE)
    except OSError as e:
        raise GitError("could not execute %s: %s\n" % (command, e))

    err = p.wait()
    if err != 0:
        raise GitError(p.stderr.read())

    tmpfile.seek(0)
    lines = []
    for l in tmpfile:
        lines.append(l.decode('utf-8', 'replace'))
    return lines

def git_root():
    """Return the root of the current git workspace"""

    p = git('rev-parse --git-dir')
    dir = p[0]

    return os.path.abspath(os.path.join(dir, os.path.pardir))

def git_branch():
    """Return the current git branch"""

    p = git('branch')

    for elt in p:
        if elt[0] == '*':
            if elt.endswith('(no branch)'):
                return None
            return elt.split()[1]

def git_parent_branch(branch):
    """Return the parent of the current git branch.

    If this branch tracks a remote branch, return the remote branch which is
    tracked.  If not, default to origin/master."""

    if not branch:
        return None

    p = git(["for-each-ref", "--format=%(refname:short) %(upstream:short)",
            "refs/heads/"])

    if not p:
        sys.stderr.write("Failed finding git parent branch\n")
        sys.exit(1)

    for line in p:
        # Git 1.7 will leave a ' ' trailing any non-tracking branch
        if ' ' in line and not line.endswith(' \n'):
            local, remote = line.split()
            if local == branch:
                return remote
    return 'origin/master'

def git_comments(parent):
    """Return a list of any checkin comments on this git branch"""

    p = git('log --pretty=tformat:%%B:SEP: %s..' % parent)

    if not p:
        sys.stderr.write("No outgoing changesets found - missing -p option?\n");
        sys.exit(1)

    return [x.strip() for x in p if x != ':SEP:\n']

def git_file_list(parent, paths=None):
    """Return the set of files which have ever changed on this branch.

    NB: This includes files which no longer exist, or no longer actually
    differ."""

    p = git("log --name-only --pretty=format: %s.. %s" %
             (parent, ' '.join(paths)))

    if not p:
        sys.stderr.write("Failed building file-list from git\n")
        sys.exit(1)

    ret = set()
    for fname in p:
        if fname and not fname.isspace() and fname not in ret:
            ret.add(fname.strip())

    return ret

def not_check(root, cmd):
    """Return a function which returns True if a file given as an argument
    should be excluded from the check named by 'cmd'"""

    ignorefiles = list(filter(os.path.exists,
                         [os.path.join(root, ".git", "%s.NOT" % cmd),
                          os.path.join(root, "exception_lists", cmd)]))
    return Ignore.ignore(root, ignorefiles)

def gen_files(root, parent, paths, exclude, filter=None):
    """Return a function producing file names, relative to the current
    directory, of any file changed on this branch (limited to 'paths' if
    requested), and excluding files for which exclude returns a true value """

    if filter is None:
        filter = lambda x: os.path.isfile(x)

    # Taken entirely from Python 2.6's os.path.relpath which we would use if we
    # could.
    def relpath(path, here):
        c = os.path.abspath(os.path.join(root, path)).split(os.path.sep)
        s = os.path.abspath(here).split(os.path.sep)
        l = len(os.path.commonprefix((s, c)))
        return os.path.join(*[os.path.pardir] * (len(s)-l) + c[l:])

    def ret(select=None):
        if not select:
            select = lambda x: True

        for abspath in git_file_list(parent, paths):
            path = relpath(abspath, '.')
            try:
                res = git("diff %s HEAD %s" % (parent, path))
            except GitError as e:
                # This ignores all the errors that can be thrown. Usually, this
                # means that git returned non-zero because the file doesn't
                # exist, but it could also fail if git can't create a new file
                # or it can't be executed.  Such errors are 1) unlikely, and 2)
                # will be caught by other invocations of git().
                continue
            empty = not res
            if (filter(path) and not empty and
                select(path) and not exclude(abspath)):
                yield path
    return ret

def gen_links(root, parent, paths, exclude):
    """Return a function producing symbolic link names, relative to the current
    directory, of any file changed on this branch (limited to 'paths' if
    requested), and excluding files for which exclude returns a true value """

    return gen_files(root, parent, paths, exclude, lambda x: os.path.islink(x))

def comchk(root, parent, flist, output):
    output.write("Comments:\n")

    return Comments.comchk(git_comments(parent), check_db=True,
                           output=output)


def mapfilechk(root, parent, flist, output):
    ret = 0

    # We are interested in examining any file that has the following
    # in its final path segment:
    #    - Contains the word 'mapfile'
    #    - Begins with 'map.'
    #    - Ends with '.map'
    # We don't want to match unless these things occur in final path segment
    # because directory names with these strings don't indicate a mapfile.
    # We also ignore files with suffixes that tell us that the files
    # are not mapfiles.
    MapfileRE = re.compile(r'.*((mapfile[^/]*)|(/map\.+[^/]*)|(\.map))$',
        re.IGNORECASE)
    NotMapSuffixRE = re.compile(r'.*\.[ch]$', re.IGNORECASE)

    output.write("Mapfile comments:\n")

    for f in flist(lambda x: MapfileRE.match(x) and not
                   NotMapSuffixRE.match(x)):
        with io.open(f, encoding='utf-8', errors='replace') as fh:
            ret |= Mapfile.mapfilechk(fh, output=output)
    return ret

def copyright(root, parent, flist, output):
    ret = 0
    output.write("Copyrights:\n")
    for f in flist():
        with io.open(f, encoding='utf-8', errors='replace') as fh:
            ret |= Copyright.copyright(fh, output=output)
    return ret

def hdrchk(root, parent, flist, output):
    ret = 0
    output.write("Header format:\n")
    for f in flist(lambda x: x.endswith('.h')):
        with io.open(f, encoding='utf-8', errors='replace') as fh:
            ret |= HdrChk.hdrchk(fh, lenient=True, output=output)
    return ret

def cstyle(root, parent, flist, output):
    ret = 0
    output.write("C style:\n")
    for f in flist(lambda x: x.endswith('.c') or x.endswith('.h')):
        with io.open(f, mode='rb') as fh:
            ret |= CStyle.cstyle(fh, output=output, picky=True,
                             check_posix_types=True,
                             check_continuation=True)
    return ret

def jstyle(root, parent, flist, output):
    ret = 0
    output.write("Java style:\n")
    for f in flist(lambda x: x.endswith('.java')):
        with io.open(f, mode='rb') as fh:
            ret |= JStyle.jstyle(fh, output=output, picky=True)
    return ret

def manlint(root, parent, flist, output):
    ret = 0
    output.write("Man page format/spelling:\n")
    ManfileRE = re.compile(r'.*\.[0-9][a-z]*$', re.IGNORECASE)
    for f in flist(lambda x: ManfileRE.match(x)):
        with io.open(f, mode='rb') as fh:
            ret |= ManLint.manlint(fh, output=output, picky=True)
            ret |= SpellCheck.spellcheck(fh, output=output)
    return ret

def shelllint(root, parent, flist, output):
    ret = 0
    output.write("Shell lint:\n")

    def isshell(x):
        (_, ext) = os.path.splitext(x)
        if ext in ['.sh', '.ksh']:
            return True
        if ext == '':
            with io.open(x, mode='r', errors='ignore') as fh:
                if re.match(r'^#.*\bk?sh\b', fh.readline()):
                    return True
        return False

    for f in flist(isshell):
        with io.open(f, mode='rb') as fh:
            ret |= ShellLint.lint(fh, output=output)

    return ret

def keywords(root, parent, flist, output):
    ret = 0
    output.write("SCCS Keywords:\n")
    for f in flist():
        with io.open(f, encoding='utf-8', errors='replace') as fh:
            ret |= Keywords.keywords(fh, output=output)
    return ret

def wscheck(root, parent, flist, output):
    ret = 0
    output.write("white space nits:\n")
    for f in flist():
        with io.open(f, encoding='utf-8', errors='replace') as fh:
            ret |= WsCheck.wscheck(fh, output=output)
    return ret

def symlinks(root, parent, flist, output):
    ret = 0
    output.write("Symbolic links:\n")
    for f in flist():
        output.write("  "+f+"\n")
        ret |= 1
    return ret

def iswinreserved(name):
    reserved = [
        'con', 'prn', 'aux', 'nul',
        'com1', 'com2', 'com3', 'com4', 'com5',
        'com6', 'com7', 'com8', 'com9', 'com0',
        'lpt1', 'lpt2', 'lpt3', 'lpt4', 'lpt5',
        'lpt6', 'lpt7', 'lpt8', 'lpt9', 'lpt0' ]
    l = name.lower()
    for r in reserved:
        if l == r or l.startswith(r+"."):
            return True
    return False

def haswinspecial(name):
    specials = '<>:"\\|?*'
    for c in name:
        if c in specials:
            return True
    return False

def winnames(root, parent, flist, output):
    ret = 0
    output.write("Illegal filenames (Windows):\n")
    for f in flist():
        if haswinspecial(f):
            output.write("  "+f+": invalid character in name\n")
            ret |= 1
            continue

        parts = f.split('/')
        for p in parts:
            if iswinreserved(p):
                output.write("  "+f+": reserved file name\n")
                ret |= 1
                break

    return ret

def run_checks(root, parent, cmds, scmds, paths='', opts={}):
    """Run the checks given in 'cmds', expected to have well-known signatures,
    and report results for any which fail.

    Return failure if any of them did.

    NB: the function name of the commands passed in is used to name the NOT
    file which excepts files from them."""

    ret = 0

    for cmd in cmds:
        s = StringIO()

        exclude = not_check(root, cmd.__name__)
        result = cmd(root, parent, gen_files(root, parent, paths, exclude),
                     output=s)
        ret |= result

        if result != 0:
            print(s.getvalue())

    for cmd in scmds:
        s = StringIO()

        exclude = not_check(root, cmd.__name__)
        result = cmd(root, parent, gen_links(root, parent, paths, exclude),
                     output=s)
        ret |= result

        if result != 0:
            print(s.getvalue())

    return ret

def nits(root, parent, paths):
    cmds = [copyright,
            cstyle,
            hdrchk,
            jstyle,
            keywords,
            manlint,
            mapfilechk,
            shelllint,
            winnames,
            wscheck]
    scmds = [symlinks]
    run_checks(root, parent, cmds, scmds, paths)

def pbchk(root, parent, paths):
    cmds = [comchk,
            copyright,
            cstyle,
            hdrchk,
            jstyle,
            keywords,
            manlint,
            mapfilechk,
            shelllint,
            winnames,
            wscheck]
    scmds = [symlinks]
    run_checks(root, parent, cmds, scmds)

def main(cmd, args):
    parent_branch = None
    checkname = None

    try:
        opts, args = getopt.getopt(args, 'b:c:p:')
    except getopt.GetoptError as e:
        sys.stderr.write(str(e) + '\n')
        sys.stderr.write("Usage: %s [-c check] [-p branch] [path...]\n" % cmd)
        sys.exit(1)

    for opt, arg in opts:
        # We accept "-b" as an alias of "-p" for backwards compatibility.
        if opt == '-p' or opt == '-b':
            parent_branch = arg
        elif opt == '-c':
            checkname = arg

    if not parent_branch:
        parent_branch = git_parent_branch(git_branch())

    if checkname is None:
        if cmd == 'git-pbchk':
            checkname = 'pbchk'
        else:
            checkname = 'nits'

    if checkname == 'pbchk':
        if args:
            sys.stderr.write("only complete workspaces may be pbchk'd\n");
            sys.exit(1)
        pbchk(git_root(), parent_branch, None)
    elif checkname == 'nits':
        nits(git_root(), parent_branch, args)
    else:
        run_checks(git_root(), parent_branch, [eval(checkname)], args)

if __name__ == '__main__':
    try:
        main(os.path.basename(sys.argv[0]), sys.argv[1:])
    except GitError as e:
        sys.stderr.write("failed to run git:\n %s\n" % str(e))
        sys.exit(1)
