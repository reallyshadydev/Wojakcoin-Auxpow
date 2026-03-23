// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2011 Vince Durham
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2016 Daniel Kraft
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "auxpow.h"

#include "chainparams.h"
#include "consensus/merkle.h"
#include "hash.h"
#include "primitives/block.h"
#include "script/script.h"
#include "util.h"
#include "utilstrencodings.h"

#include <algorithm>

namespace {

uint32_t DecodeLE32(const unsigned char* bytes)
{
    uint32_t res = 0;
    for (int i = 0; i < 4; ++i) {
        res <<= 8;
        res |= bytes[3 - i];
    }
    return res;
}

} // namespace

bool CAuxPow::check(const uint256& hashAuxBlock, int nChainId,
    const Consensus::Params& params) const
{
    if (params.fStrictChainId && parentBlock.GetChainId() == nChainId) {
        return error("Aux POW parent has our chain ID");
    }

    if (nIndex != 0)
        return error("AuxPow is not a generate");

    if (vChainMerkleBranch.size() > 30)
        return error("Aux POW chain merkle branch too long");

    const uint256 nRootHash = CheckMerkleBranch(hashAuxBlock, vChainMerkleBranch, nChainIndex);
    std::vector<unsigned char> vchRootHash(nRootHash.begin(), nRootHash.end());
    std::reverse(vchRootHash.begin(), vchRootHash.end());

    if (CheckMerkleBranch(GetHash(), vMerkleBranch, nIndex) != parentBlock.hashMerkleRoot)
        return error("Aux POW merkle root incorrect");

    if (tx.vin.empty())
        return error("Aux POW coinbase has no inputs");

    const CScript& script = tx.vin[0].scriptSig;

    const unsigned char* const mmHeaderBegin = pchMergedMiningHeader;
    const unsigned char* const mmHeaderEnd = mmHeaderBegin + sizeof(pchMergedMiningHeader);
    CScript::const_iterator pcHead =
        std::search(script.begin(), script.end(), mmHeaderBegin, mmHeaderEnd);

    CScript::const_iterator pc =
        std::search(script.begin(), script.end(), vchRootHash.begin(), vchRootHash.end());

    if (pc == script.end())
        return error("Aux POW missing chain merkle root in parent coinbase");

    if (pcHead != script.end()) {
        if (script.end() != std::search(pcHead + 1, script.end(), mmHeaderBegin, mmHeaderEnd))
            return error("Multiple merged mining headers in coinbase");
        if (pcHead + sizeof(pchMergedMiningHeader) != pc)
            return error("Merged mining header is not just before chain merkle root");
    } else {
        if (pc - script.begin() > 20)
            return error("Aux POW chain merkle root must start in the first 20 bytes of the parent coinbase");
    }

    pc += vchRootHash.size();
    if (script.end() - pc < 8)
        return error("Aux POW missing chain merkle tree size and nonce in parent coinbase");

    const uint32_t nSize = DecodeLE32(&pc[0]);
    const unsigned merkleHeight = vChainMerkleBranch.size();
    if (nSize != (1u << merkleHeight))
        return error("Aux POW merkle branch size does not match parent coinbase");

    const uint32_t nNonce = DecodeLE32(&pc[4]);
    if (nChainIndex != getExpectedIndex(nNonce, nChainId, merkleHeight))
        return error("Aux POW wrong index");

    return true;
}

int CAuxPow::getExpectedIndex(uint32_t nNonce, int nChainId, unsigned h)
{
    const uint32_t mod = (1u << h);

    uint64_t rand = nNonce;
    rand = rand * 1103515245 + 12345;
    rand %= mod;
    rand += nChainId;
    rand = rand * 1103515245 + 12345;
    rand %= mod;

    return static_cast<int>(rand);
}

uint256 CAuxPow::CheckMerkleBranch(uint256 hash,
    const std::vector<uint256>& vMerkleBranch,
    int nIndex)
{
    if (nIndex == -1)
        return uint256();
    for (std::vector<uint256>::const_iterator it(vMerkleBranch.begin());
         it != vMerkleBranch.end(); ++it) {
        if (nIndex & 1)
            hash = Hash(BEGIN(*it), END(*it), BEGIN(hash), END(hash));
        else
            hash = Hash(BEGIN(hash), END(hash), BEGIN(*it), END(*it));
        nIndex >>= 1;
    }
    return hash;
}

void CAuxPow::updateMergedMiningHeader(CBlockHeader& header)
{
    if (!header.auxpow)
        return;

    const uint256 blockHash = header.GetHash();
    std::vector<unsigned char> inputData(blockHash.begin(), blockHash.end());
    std::reverse(inputData.begin(), inputData.end());
    inputData.push_back(1);
    inputData.insert(inputData.end(), 7, 0);

    CMutableTransaction coinbase(header.auxpow->tx);
    if (coinbase.vin.empty())
        return;
    coinbase.vin[0].scriptSig = (CScript() << inputData);
    header.auxpow->tx = coinbase;

    CBlock parent;
    parent.nVersion = header.auxpow->parentBlock.nVersion;
    parent.hashPrevBlock = header.auxpow->parentBlock.hashPrevBlock;
    parent.hashMerkleRoot = header.auxpow->parentBlock.hashMerkleRoot;
    parent.nTime = header.auxpow->parentBlock.nTime;
    parent.nBits = header.auxpow->parentBlock.nBits;
    parent.nNonce = header.auxpow->parentBlock.nNonce;
    parent.vtx.resize(1);
    parent.vtx[0] = coinbase;
    parent.hashMerkleRoot = BlockMerkleRoot(parent);
    header.auxpow->parentBlock = parent.GetBlockHeader();
    header.auxpow->vMerkleBranch.clear();
    header.auxpow->nIndex = 0;
}

void CAuxPow::initAuxPow(CBlockHeader& header)
{
    header.SetAuxpowFlag(true);

    const uint256 blockHash = header.GetHash();
    std::vector<unsigned char> inputData(blockHash.begin(), blockHash.end());
    std::reverse(inputData.begin(), inputData.end());
    inputData.push_back(1);
    inputData.insert(inputData.end(), 7, 0);

    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vin[0].scriptSig = (CScript() << inputData);
    assert(coinbase.vout.empty());

    CBlock parent;
    parent.nVersion = 1;
    parent.vtx.resize(1);
    parent.vtx[0] = coinbase;
    parent.hashPrevBlock.SetNull();
    parent.hashMerkleRoot = BlockMerkleRoot(parent);
    parent.nTime = header.nTime;
    parent.nBits = header.nBits;
    parent.nNonce = header.nNonce;

    std::shared_ptr<CAuxPow> apow(new CAuxPow(CTransaction(coinbase)));
    apow->vChainMerkleBranch.clear();
    apow->nChainIndex = 0;
    apow->vMerkleBranch.clear();
    apow->nIndex = 0;
    apow->parentBlock = parent.GetBlockHeader();

    header.SetAuxpow(apow);
}
