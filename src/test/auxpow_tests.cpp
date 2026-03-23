// Copyright (c) 2025 The WojakCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "auxpow.h"
#include "chainparams.h"
#include "chainparamsbase.h"
#include "consensus/merkle.h"
#include "pow.h"
#include "primitives/block.h"
#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(auxpow_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(auxpow_roundtrip_init)
{
    SelectParams(CBaseChainParams::REGTEST);
    const Consensus::Params& params = Params().GetConsensus();
    CBlockHeader h;
    h.nVersion = 4;
    h.SetBaseVersion(4, params.nAuxpowChainId);
    h.hashPrevBlock.SetNull();
    h.hashMerkleRoot.SetNull();
    h.nTime = 1234567890;
    h.nBits = 0x207fffff;
    h.nNonce = 0;

    CAuxPow::initAuxPow(h);
    BOOST_CHECK(h.IsAuxpow());
    BOOST_CHECK(h.auxpow);
    BOOST_CHECK(h.auxpow->check(h.GetHash(), params.nAuxpowChainId, params));

    uint32_t n = 0;
    while (n < 5000000) {
        h.auxpow->parentBlock.nNonce = n;
        if (CheckProofOfWork(h.auxpow->getParentBlockPoWHash(), h.auxpow->parentBlock.nBits, params))
            break;
        ++n;
    }
    BOOST_CHECK(CheckProofOfWork(h.auxpow->getParentBlockPoWHash(), h.auxpow->parentBlock.nBits, params));
    BOOST_CHECK(CheckBlockHeaderProofOfWork(h, params, -1));
}

BOOST_AUTO_TEST_SUITE_END()
