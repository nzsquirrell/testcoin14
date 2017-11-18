// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/pureheader.h"

#include "hash.h"
#include "utilstrencodings.h"
#include "crypto/hashskein.h"
#include "crypto/hashgroestl.h"

uint256 CPureBlockHeader::GetHash() const
{
    return SerializeHash(*this);
}

uint256 CPureBlockHeader::GetPoWHash(int algo, const Consensus::Params& consensusParams) const
{
    switch (algo)
    {
        case ALGO_SLOT1:
            return HashSkein(BEGIN(nVersion), END(nNonce));
        case ALGO_SLOT2:
            return HashGroestl(BEGIN(nVersion), END(nNonce));
        case ALGO_SLOT3:
            return GetHash();
    }
    // catch-all if above doesn't match anything to algo
    return HashSkein(BEGIN(nVersion), END(nNonce));
}

void CPureBlockHeader::SetBaseVersion(int32_t nBaseVersion, int32_t nChainId)
{
    assert(nBaseVersion >= 1 && nBaseVersion < VERSION_AUXPOW);
    assert(!IsAuxpow());
    nVersion = nBaseVersion | (nChainId * VERSION_CHAIN_START);
}

int GetAlgo(int nVersion)
{
    switch (nVersion & BLOCK_VERSION_ALGO)
    {
        case 0:
            return ALGO_SLOT1;
        case BLOCK_VERSION_SLOT2:
            return ALGO_SLOT2;
        case BLOCK_VERSION_SLOT3:
            return ALGO_SLOT3;
    }
    return ALGO_SLOT1;
}
