// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2015 The Dogecoin Core developers
// Copyright (c) 2020-2021 Uladzimir (https://t.me/vovanchik_net)
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POW_H
#define BITCOIN_POW_H

#include <consensus/params.h>

#include <stdint.h>

class CBlockHeader;
class CBlockIndex;
class uint256;

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params&);

#endif // BITCOIN_POW_H
