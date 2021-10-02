// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2015 The Dogecoin Core developers
// Copyright (c) 2020-2021 Uladzimir (https://t.me/vovanchik_net)
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_BLOCK_H
#define BITCOIN_PRIMITIVES_BLOCK_H

#include <primitives/transaction.h>
#include <serialize.h>
#include <uint256.h>
#include <consensus/params.h>

/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements.  When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain.  The first transaction
 * in the block is a special one that creates a new coin owned by the creator
 * of the block.
 */
class CAuxPow; 
 
class CBlockHeader
{
public:
    /* Modifiers to the version.  */
    static const int32_t VERSION_AUXPOW = (1 << 8);

    // header
    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;

    std::shared_ptr<CAuxPow> auxpow;

    CBlockHeader()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(this->nVersion);
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        READWRITE(nTime);
        READWRITE(nBits);
        READWRITE(nNonce);
        if (!(s.GetType() & SER_GETHASH)) {
            if (this->IsAuxpow()) {
                if (ser_action.ForRead()) SetAuxpowInitDef();
                assert(auxpow);
                READWRITE(*auxpow);
            } else if (ser_action.ForRead()) auxpow.reset();
        }    
    }

    void SetNull()
    {
        nVersion = 0;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        nTime = 0;
        nBits = 0;
        nNonce = 0;
        auxpow.reset();
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }

    uint256 GetHash() const;

    uint256 GetPoWHash() const;

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }
    
    inline int32_t GetBaseVersion() const {
        return nVersion & 0xFF;
    }
    
    void SetBaseVersion(int32_t nBaseVersion, int32_t nChainId) {
        assert(nBaseVersion >= 1 && nBaseVersion < VERSION_AUXPOW);
        assert(!IsAuxpow());
        nVersion = nBaseVersion | (nChainId << 16);
    }

    inline int32_t GetChainId() const {
        return nVersion >> 16;
    }

    inline bool IsAuxpow() const {
        return nVersion & VERSION_AUXPOW;
    }

    inline bool IsLegacy() const {
        return (nVersion == 1) || (nVersion == 2 && GetChainId() == 0);
    }
    
    void SetAuxpowInitDef();
};

class CBlock : public CBlockHeader
{
public:
    // network and disk
    std::vector<CTransactionRef> vtx;

    // memory only
    mutable bool fChecked;

    CBlock()
    {
        SetNull();
    }

    CBlock(const CBlockHeader &header)
    {
        SetNull();
        *(static_cast<CBlockHeader*>(this)) = header;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITEAS(CBlockHeader, *this);
        READWRITE(vtx);
    }

    void SetNull()
    {
        CBlockHeader::SetNull();
        vtx.clear();
        fChecked = false;
    }

    CBlockHeader GetBlockHeader() const
    {
        CBlockHeader block;
        block.nVersion       = nVersion;
        block.hashPrevBlock  = hashPrevBlock;
        block.hashMerkleRoot = hashMerkleRoot;
        block.nTime          = nTime;
        block.nBits          = nBits;
        block.nNonce         = nNonce;
        block.auxpow         = auxpow;
        return block;
    }

    std::string ToString() const;
};

/** Describes a place in the block chain to another node such that if the
 * other node doesn't have the same branch, it can find a recent common trunk.
 * The further back it is, the further before the fork it may be.
 */
struct CBlockLocator
{
    std::vector<uint256> vHave;

    CBlockLocator() {}

    explicit CBlockLocator(const std::vector<uint256>& vHaveIn) : vHave(vHaveIn) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vHave);
    }

    void SetNull()
    {
        vHave.clear();
    }

    bool IsNull() const
    {
        return vHave.empty();
    }
};

class CAuxPow {
  public:
    // CMerkleTx
    CTransactionRef tx;
    uint256 hashBlock;
    std::vector<uint256> vMerkleBranch;
    int nIndex;
    /** The merkle branch connecting the aux block to our coinbase.  */
    std::vector<uint256> vChainMerkleBranch;
    /** Merkle tree index of the aux block header in the coinbase.  */
    int nChainIndex;
    /** Parent block header (on which the real PoW is done).  */
    CBlockHeader parentBlock;
  public:
    /* Prevent accidental conversion.  */
    inline CAuxPow() : nIndex(-1), tx(std::move(MakeTransactionRef())) { }

    ADD_SERIALIZE_METHODS;

    template<typename Stream, typename Operation>
        inline void SerializationOp (Stream& s, Operation ser_action) {
        READWRITE(tx);
        READWRITE(hashBlock);
        READWRITE(vMerkleBranch);
        READWRITE(nIndex);
        READWRITE(vChainMerkleBranch);
        READWRITE(nChainIndex);
        READWRITE(parentBlock.nVersion);
        READWRITE(parentBlock.hashPrevBlock);
        READWRITE(parentBlock.hashMerkleRoot);
        READWRITE(parentBlock.nTime);
        READWRITE(parentBlock.nBits);
        READWRITE(parentBlock.nNonce);
    }

    bool check(const uint256& hashAuxBlock, int nChainId, const Consensus::Params& params) const;
};

#endif // BITCOIN_PRIMITIVES_BLOCK_H
