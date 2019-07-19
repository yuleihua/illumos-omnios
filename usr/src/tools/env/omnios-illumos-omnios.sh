
######################################################################
# OmniOS-specific overrides

# Enable the non-DEBUG build
NIGHTLY_OPTIONS=${NIGHTLY_OPTIONS/F/}

export ON_CLOSED_BINS=/opt/onbld/closed

export GNUC_ROOT=/opt/gcc-4.4.4/
export PRIMARY_CC=gcc4,/opt/gcc-4.4.4/bin/gcc,gnu
export PRIMARY_CCC=gcc4,/opt/gcc-4.4.4/bin/g++,gnu
export SHADOW_CCS=gcc7,/opt/gcc-7/bin/gcc,gnu
export SHADOW_CCCS=gcc7,/opt/gcc-7/bin/g++,gnu

ENABLE_SMB_PRINTING='#'

_branch=`git -C $CODEMGR_WS rev-parse --abbrev-ref HEAD`
_hash=`git -C $CODEMGR_WS rev-parse --short HEAD`
export VERSION=`echo omnios-$_branch-$_hash | tr '/' '-'`

export ONNV_BUILDNUM=`grep '^VERSION=r' /etc/os-release | cut -c10-15`
export PKGVERS_BRANCH=$ONNV_BUILDNUM.0

