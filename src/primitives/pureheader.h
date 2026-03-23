// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_PUREHEADER_H
#define BITCOIN_PRIMITIVES_PUREHEADER_H

#include "serialize.h"
#include "uint256.h"

/**
 * Block header fields used for hashing (no auxpow). Parent headers in merge-mining
 * use this type so auxpow does not recurse.
 */
class CPureBlockHeader
{
public:
    static const int32_t VERSION_AUXPOW = (1 << 8);
    static const int32_t VERSION_CHAIN_START = (1 << 16);

    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;

    CPureBlockHeader()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        READWRITE(nTime);
        READWRITE(nBits);
        READWRITE(nNonce);
    }

    void SetNull()
    {
        nVersion = 0;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        nTime = 0;
        nBits = 0;
        nNonce = 0;
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }

    uint256 GetHash() const;

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }

    int32_t GetBaseVersion() const
    {
        return GetBaseVersion(nVersion);
    }

    static int32_t GetBaseVersion(int32_t ver)
    {
        return ver % VERSION_AUXPOW;
    }

    void SetBaseVersion(int32_t nBaseVersion, int32_t nChainId);

    int32_t GetChainId() const
    {
        return nVersion >> 16;
    }

    void SetChainId(int32_t chainId)
    {
        nVersion %= VERSION_CHAIN_START;
        nVersion |= chainId * VERSION_CHAIN_START;
    }

    bool IsAuxpow() const
    {
        return nVersion & VERSION_AUXPOW;
    }

    void SetAuxpowFlag(bool auxpow)
    {
        if (auxpow)
            nVersion |= VERSION_AUXPOW;
        else
            nVersion &= ~VERSION_AUXPOW;
    }
};

#endif // BITCOIN_PRIMITIVES_PUREHEADER_H
