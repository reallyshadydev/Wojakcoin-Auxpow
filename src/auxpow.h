// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2011 Vince Durham
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2016 Daniel Kraft
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_AUXPOW_H
#define BITCOIN_AUXPOW_H

#include "consensus/params.h"
#include "primitives/pureheader.h"
#include "primitives/transaction.h"
#include "serialize.h"
#include "uint256.h"

#include <vector>

class CBlock;
class CBlockHeader;
class CBlockIndex;

/** Header for merge-mining data in the coinbase. */
static const unsigned char pchMergedMiningHeader[] = { 0xfa, 0xbe, 'm', 'm' };

/** A transaction with a merkle branch linking it to a block merkle root. */
class CMerkleTx
{
public:
    CTransaction tx;
    uint256 hashBlock;
    std::vector<uint256> vMerkleBranch;
    int nIndex;

    CMerkleTx()
    {
        SetNull();
    }

    void SetNull()
    {
        tx = CTransaction();
        hashBlock.SetNull();
        vMerkleBranch.clear();
        nIndex = -1;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(tx);
        READWRITE(hashBlock);
        READWRITE(vMerkleBranch);
        READWRITE(nIndex);
    }

    uint256 GetHash() const { return tx.GetHash(); }
};

/**
 * Merge-mining auxpow: parent block coinbase proves inclusion of this chain's
 * block hash in the merge-mining merkle tree.
 */
class CAuxPow : public CMerkleTx
{
public:
    std::vector<uint256> vChainMerkleBranch;
    int nChainIndex;
    CPureBlockHeader parentBlock;

    CAuxPow() : CMerkleTx(), nChainIndex(0) { }

    explicit CAuxPow(const CTransaction& txIn) : CMerkleTx()
    {
        tx = txIn;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(*(CMerkleTx*)this);
        READWRITE(vChainMerkleBranch);
        READWRITE(nChainIndex);
        READWRITE(parentBlock);
    }

    bool check(const uint256& hashAuxBlock, int nChainId, const Consensus::Params& params) const;

    uint256 getParentBlockPoWHash() const
    {
        return parentBlock.GetHash();
    }

    static int getExpectedIndex(uint32_t nNonce, int nChainId, unsigned h);

    static uint256 CheckMerkleBranch(uint256 hash,
        const std::vector<uint256>& vMerkleBranch,
        int nIndex);

    static void initAuxPow(CBlockHeader& header);

    /** After the child header or coinbase changes, re-embed the child hash in the parent coinbase. */
    static void updateMergedMiningHeader(CBlockHeader& header);
};

#endif // BITCOIN_AUXPOW_H
