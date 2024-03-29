// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2015 The Dogecoin Core developers
// Copyright (c) 2020-2021 Uladzimir (https://t.me/vovanchik_net)
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_PARAMS_H
#define BITCOIN_CONSENSUS_PARAMS_H

#include <uint256.h>
#include <arith_uint256.h>
#include <limits>
#include <map>
#include <string>

namespace Consensus {

enum DeploymentPos
{
    DEPLOYMENT_TESTDUMMY,
    // NOTE: Also add new deployments to VersionBitsDeploymentInfo in versionbits.cpp
    MAX_VERSION_BITS_DEPLOYMENTS
};

/**
 * Struct for each individual consensus rule change using BIP9.
 */
struct BIP9Deployment {
    /** Bit position to select the particular bit in nVersion. */
    int bit;
    /** Start MedianTime for version bits miner confirmation. Can be a date in the past */
    int64_t nStartTime;
    /** Timeout/expiry MedianTime for the deployment attempt. */
    int64_t nTimeout;

    /** Constant for nTimeout very far in the future. */
    static constexpr int64_t NO_TIMEOUT = std::numeric_limits<int64_t>::max();

    /** Special value for nStartTime indicating that the deployment is always active.
     *  This is useful for testing, as it means tests don't need to deal with the activation
     *  process (which takes at least 3 BIP9 intervals). Only tests that specifically test the
     *  behaviour during activation cannot use this. */
    static constexpr int64_t ALWAYS_ACTIVE = -1;
};

/**
 * Parameters that influence chain consensus.
 */
struct Params {
    uint256 hashGenesisBlock;
    int nSubsidyHalvingInterval;
    /** Block height and hash at which BIP34 becomes active */
    int BIP34Height;
    uint256 BIP34Hash;
    /** Block height at which BIP65 becomes active */
    int BIP65Height;
    /** Block height at which BIP66 becomes active */
    int BIP66Height;
    int CSVHeight;
    int WitnessHeight;
    /**
     * Minimum blocks including miner confirmation of the total of 2016 blocks in a retargeting period,
     * (nPowTargetTimespan / nPowTargetSpacing) which is also used for BIP9 deployments.
     * Examples: 1916 for 95%, 1512 for testchains.
     */
    uint32_t nCoinbaseMaturityBegin;
    int CoinbaseMaturity240Height;
    int32_t nCoinbaseMaturity(int Height) const { 
        return (Height >= CoinbaseMaturity240Height) ? 240 : nCoinbaseMaturityBegin;
    }
    /** Proof of work parameters */
    arith_uint256 powLimit;
    bool fPowAllowMinDifficultyBlocks;
    int64_t nPowTargetSpacing;
    int64_t nPowTargetTimespanBegin;
    int PowTargetTimespan60Height;
    int64_t nPowTargetTimespan(int Height) const { 
        return (Height >= PowTargetTimespan60Height) ? 60 : nPowTargetTimespanBegin;
    }
    int64_t DifficultyAdjustmentInterval(int Height) const { 
        return nPowTargetTimespan(Height) / nPowTargetSpacing;
    }
    uint256 nMinimumChainWork;
    uint256 defaultAssumeValid;
    /** Auxpow parameters */
    int32_t nAuxpowChainId;
    bool fStrictChainId;
    int DigishieldDifficultyCalculationHeight;
    int SimplifiedRewardsHeight;
    int DisallowLegacyBlocksHeight;
};
} // namespace Consensus

#endif // BITCOIN_CONSENSUS_PARAMS_H
