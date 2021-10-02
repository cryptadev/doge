// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2015 The Dogecoin Core developers
// Copyright (c) 2020-2021 Uladzimir (https://t.me/vovanchik_net)
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <primitives/block.h>
#include <uint256.h>
#include <util.h>

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    int nHeight = pindexLast->nHeight + 1;
    const int64_t retargetTimespan = params.nPowTargetTimespan(nHeight);
    const int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    int64_t nModulatedTimespan = nActualTimespan;
    int64_t nMaxTimespan;
    int64_t nMinTimespan;

    if (nHeight >= params.DigishieldDifficultyCalculationHeight) {
        // amplitude filter - thanks to daft27 for this code
        nModulatedTimespan = retargetTimespan + (nModulatedTimespan - retargetTimespan) / 8;
        nMinTimespan = retargetTimespan - (retargetTimespan / 4);
        nMaxTimespan = retargetTimespan + (retargetTimespan / 2);
    } else if (nHeight > 10000) {
        nMinTimespan = retargetTimespan / 4;
        nMaxTimespan = retargetTimespan * 4;
    } else if (nHeight > 5000) {
        nMinTimespan = retargetTimespan / 8;
        nMaxTimespan = retargetTimespan * 4;
    } else {
        nMinTimespan = retargetTimespan / 16;
        nMaxTimespan = retargetTimespan * 4;
    }

    // Limit adjustment step
    if (nModulatedTimespan < nMinTimespan) nModulatedTimespan = nMinTimespan;
    else if (nModulatedTimespan > nMaxTimespan) nModulatedTimespan = nMaxTimespan;

    // Retarget
    arith_uint256 bnNew;
    arith_uint256 bnOld;
    bnNew.SetCompact(pindexLast->nBits);
    bnOld = bnNew;
    bnNew *= nModulatedTimespan;
    bnNew /= retargetTimespan;
    if (bnNew > params.powLimit) bnNew = params.powLimit;
    return bnNew.GetCompact();
}

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    unsigned int nProofOfWorkLimit = params.powLimit.GetCompact();

    if (params.fPowAllowMinDifficultyBlocks && (pindexLast->nHeight >= 157500) &&
            (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)) {
        // Special difficulty rule for testnet:
        // If the new block's timestamp is more than 2* nTargetSpacing minutes
        // then allow mining of a min-difficulty block.
        return nProofOfWorkLimit;
    }

    // Only change once per difficulty adjustment interval
    const int64_t difficultyAdjustmentInterval = params.DifficultyAdjustmentInterval(pindexLast->nHeight);
    if ((pindexLast->nHeight+1) % difficultyAdjustmentInterval != 0)
    {
        if (params.fPowAllowMinDifficultyBlocks)
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then allow mining of a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)
                return nProofOfWorkLimit;
            else
            {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % difficultyAdjustmentInterval != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    }

    // Litecoin: This fixes an issue where a 51% attack can change difficulty at will.
    // Go back the full period unless it's the first retarget after genesis. Code courtesy of Art Forz
    int blockstogoback = difficultyAdjustmentInterval-1;
    if ((pindexLast->nHeight+1) != difficultyAdjustmentInterval)
        blockstogoback = difficultyAdjustmentInterval;

    // Go back by what we want to be worth of blocks
    int nHeightFirst = pindexLast->nHeight - blockstogoback;
    assert(nHeightFirst >= 0);
    const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
    assert(pindexFirst);

    return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);
}
