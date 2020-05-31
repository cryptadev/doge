// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2015 The Dogecoin Core developers
// Copyright (c) 2020 Uladzimir (https://t.me/vovanchik_net) for Doge
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>

#include <hash.h>
#include <tinyformat.h>
#include <utilstrencodings.h>
#include <crypto/common.h>
#include <crypto/scrypt.h>
#include <chainparams.h> 

#include <consensus/merkle.h> 
#include <util.h> 

uint256 CBlockHeader::GetHash() const
{
    return SerializeHash(*this);
}

uint256 CBlockHeader::GetPoWHash() const
{
    uint256 thash;
    scrypt_1024_1_1_256(BEGIN(nVersion), BEGIN(thash));
    return thash;
}

void CBlockHeader::SetAuxpow (CAuxPow* apow) {
    if (apow) {
        auxpow.reset(apow);
        SetAuxpowFlag(true);
    } else {
        auxpow.reset();
        SetAuxpowFlag(false);
    }
}

void CBlockHeader::SetAuxpowInitDef() {
    auxpow.reset(new CAuxPow());    
}

void CBlockHeader::buildSimpleAuxPow () {
    /* Build a minimal coinbase script input for merge-mining.  */
    const uint256 blockHash = GetHash ();
    std::vector<unsigned char> inputData(blockHash.begin (), blockHash.end ());
    std::reverse (inputData.begin (), inputData.end ());
    inputData.push_back (1);
    inputData.insert (inputData.end (), 7, 0);

    /* Fake a parent-block coinbase with just the required input script and no outputs.  */
    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vin[0].scriptSig = (CScript () << inputData);
    CTransactionRef coinbaseRef = MakeTransactionRef(coinbase);

    /* Build a fake parent block with the coinbase.  */
    CBlock parent;
    parent.nVersion = 1;
    parent.vtx.resize(1);
    parent.vtx[0] = coinbaseRef;
    parent.hashMerkleRoot = BlockMerkleRoot(parent);

    /* Construct the auxpow object.  */
    SetAuxpowFlag (true);
    SetAuxpowInitDef ();
    auxpow->tx = std::move(coinbaseRef);
    auxpow->vMerkleBranch.clear();
    auxpow->vChainMerkleBranch.clear();
    auxpow->nChainIndex = 0;
    auxpow->parentBlock = parent;
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}

uint256 CheckMerkleBranch (uint256 hash, const std::vector<uint256>& vMerkleBranch, int nIndex) {
    if (nIndex == -1) return uint256 ();
    for (std::vector<uint256>::const_iterator it(vMerkleBranch.begin ()); it != vMerkleBranch.end (); ++it) {
        if (nIndex & 1)
            hash = Hash (BEGIN (*it), END (*it), BEGIN (hash), END (hash));
        else
            hash = Hash (BEGIN (hash), END (hash), BEGIN (*it), END (*it));
        nIndex >>= 1;
    }
    return hash;
}

int getExpectedIndex (uint32_t nNonce, int nChainId, unsigned h) {
    uint32_t rand = nNonce;
    rand = rand * 1103515245 + 12345;
    rand += nChainId;
    rand = rand * 1103515245 + 12345;
    return rand % (1 << h);
}

bool CAuxPow::check (const uint256& hashAuxBlock, int nChainId, const Consensus::Params& params) const {
    if (params.fStrictChainId && parentBlock.GetChainId () == nChainId)
        return error("Aux POW parent has our chain ID");
    if (vChainMerkleBranch.size() > 30)
        return error("Aux POW chain merkle branch too long");
        
    // Check that the chain merkle root is in the coinbase
    const uint256 nRootHash = CheckMerkleBranch (hashAuxBlock, vChainMerkleBranch, nChainIndex);
    std::vector<unsigned char> vchRootHash(nRootHash.begin(), nRootHash.end());
    std::reverse(vchRootHash.begin(), vchRootHash.end()); // correct endian

    // Check that we are in the parent block merkle tree
    if (CheckMerkleBranch(tx->GetHash(), vMerkleBranch, 0) != parentBlock.hashMerkleRoot)
        return error("Aux POW merkle root incorrect");

    static const unsigned char pchMergedHdr[] = { 0xfa, 0xbe, 'm', 'm' };
    const CScript script = tx->vin[0].scriptSig;
    CScript::const_iterator pcHead =
        std::search(script.begin(), script.end(), UBEGIN(pchMergedHdr), UEND(pchMergedHdr));
    CScript::const_iterator pc =
        std::search(script.begin(), script.end(), vchRootHash.begin(), vchRootHash.end());
       
    if (pc == script.end())
        return error("Aux POW missing chain merkle root in parent coinbase");
    if (pcHead != script.end()) {
        if (script.end() != std::search(pcHead + 1, script.end(), UBEGIN(pchMergedHdr), UEND(pchMergedHdr)))
            return error("Multiple merged mining headers in coinbase");
        if (pcHead + sizeof(pchMergedHdr) != pc)
            return error("Merged mining header is not just before chain merkle root");
    } else {
        // For backward compatibility.
        if (pc - script.begin() > 20)
            return error("Aux POW chain merkle root must start in the first 20 bytes of the parent coinbase");
    }

    // Ensure we are at a deterministic point in the merkle leaves by hashing
    // a nonce and our chain ID and comparing to the index.
    pc += vchRootHash.size();
    if (script.end() - pc < 8)
        return error("Aux POW missing chain merkle tree size and nonce in parent coinbase");

    uint32_t nSize;
    memcpy(&nSize, &pc[0], 4);
    nSize = le32toh(nSize);
    const unsigned merkleHeight = vChainMerkleBranch.size();
    if (nSize != (1u << merkleHeight))
        return error("Aux POW merkle branch size does not match parent coinbase");

    uint32_t nNonce;
    memcpy(&nNonce, &pc[4], 4);
    nNonce = le32toh (nNonce);
    if (nChainIndex != getExpectedIndex (nNonce, nChainId, merkleHeight))
        return error("Aux POW wrong index");

    return true;
}
