// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pow.h"

#include "arith_uint256.h"
#include "chain.h"
#include "primitives/block.h"
#include "uint256.h"
#include "util.h"

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    const arith_uint256 nProofOfWorkLimit = UintToArith256(params.powLimit);

    // Genesis block
    if (pindexLast == NULL)
        return nProofOfWorkLimit.GetCompact();

    const CBlockIndex* pindexFirst = pindexLast;

    int64_t nMinActualTimespan = params.nPoWAveragingTargetTimespan() * (100 - params.nMaxAdjustUp) / 100;
    int64_t nMaxActualTimespan = params.nPoWAveragingTargetTimespan() * (100 - params.nMaxAdjustDown) / 100;

    // Go back by what we want to be nAveragingInterval blocks
    for (int i = 0; pindexFirst && i < params.nPoWAveragingInterval - 1; i++)
    {
        pindexFirst = pindexFirst->pprev;
        if (pindexFirst == NULL)
            return nProofOfWorkLimit.GetCompact();
    }

    int64_t nActualTimespan = pindexLast->GetMedianTimePast() - pindexFirst->GetMedianTimePast();

    LogPrintf("  nActualTimespan = %d before bounds   %d   %d\n", nActualTimespan, pindexLast->GetBlockTime(), pindexFirst->GetBlockTime());

    if (nActualTimespan < nMinActualTimespan)
        nActualTimespan = nMinActualTimespan;
    if (nActualTimespan > nMaxActualTimespan)
        nActualTimespan = nMaxActualTimespan;

    LogPrintf("  nActualTimespan = %d after bounds   %d   %d\n", nActualTimespan, nMinActualTimespan, nMaxActualTimespan);

    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    arith_uint256 bnOld;
    bnOld = bnNew;

    bnNew *= nActualTimespan;
    bnNew /= params.nPoWAveragingTargetTimespan();
    if(bnNew > nProofOfWorkLimit)
        bnNew = nProofOfWorkLimit;

    LogPrintf("GetNextWorkRequired RETARGET\n");
    LogPrintf("nTargetTimespan = %d    nActualTimespan = %d\n", params.nPoWAveragingTargetTimespan(), nActualTimespan);
    LogPrintf("Before: %08x  %s\n", pindexLast->nBits, bnOld.ToString());
    LogPrintf("After:  %08x  %s\n", bnNew.GetCompact(), bnNew.ToString());

    return bnNew.GetCompact();
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespan/4)
        nActualTimespan = params.nPowTargetTimespan/4;
    if (nActualTimespan > params.nPowTargetTimespan*4)
        nActualTimespan = params.nPowTargetTimespan*4;

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespan;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
