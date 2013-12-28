// Copyright (c) 2012 The Bitcoin developers
// Copyright (c) 2013 Primecoin developers
// Distributed under conditional MIT/X11 software license,
// see the accompanying file COPYING.
#ifndef BITCOIN_VERSION_H
#define BITCOIN_VERSION_H

#ifndef CLIENTVERSION_H
#define CLIENTVERSION_H

//
// client versioning and copyright year
//

// These need to be macros, as version.cpp's and bitcoin-qt.rc's voodoo requires it
#define CLIENT_VERSION_MAJOR       0
#define CLIENT_VERSION_MINOR       8
#define CLIENT_VERSION_REVISION    3
#define CLIENT_VERSION_BUILD       0

// Set to true for release, false for prerelease or test build
#define CLIENT_VERSION_IS_RELEASE  true

// primecoin client version - intended for display purpose ONLY
#define PRIMECOIN_VERSION_MAJOR       0
#define PRIMECOIN_VERSION_MINOR       1
#define PRIMECOIN_VERSION_REVISION    2
#define PRIMECOIN_VERSION_BUILD       0

// Copyright year (2009-this)
// Todo: update this when changing our copyright comments in the source
#define COPYRIGHT_YEAR 2013

// Converts the parameter X to a string after macro replacement on X has been performed.
// Don't merge these into one macro!
#define STRINGIZE(X) DO_STRINGIZE(X)
#define DO_STRINGIZE(X) #X

#endif // CLIENTVERSION_H
#include <string>

//
// client versioning
//

static const int CLIENT_VERSION =
                           1000000 * CLIENT_VERSION_MAJOR
                         +   10000 * CLIENT_VERSION_MINOR
                         +     100 * CLIENT_VERSION_REVISION
                         +       1 * CLIENT_VERSION_BUILD;

extern const std::string CLIENT_NAME;
extern const std::string CLIENT_BUILD;
extern const std::string CLIENT_DATE;

//
// network protocol versioning
//

static const int PROTOCOL_VERSION = 70001;

// earlier versions not supported as of Feb 2012, and are disconnected
static const int MIN_PROTO_VERSION = 209;

// nTime field added to CAddress, starting with this version;
// if possible, avoid requesting addresses nodes older than this
static const int CADDR_TIME_VERSION = 31402;

// only request blocks from nodes outside this range of versions
static const int NOBLKS_VERSION_START = 32000;
static const int NOBLKS_VERSION_END = 32400;

// BIP 0031, pong message, is enabled for all versions AFTER this one
static const int BIP0031_VERSION = 60000;

// "mempool" command, enhanced "getdata" behavior starts with this version:
static const int MEMPOOL_GD_VERSION = 60002;

#endif
