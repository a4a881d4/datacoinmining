#ifndef _BLOCK_H
#define _BLOCK_H

#include"bignum.h"
#include"hash.h"

class CBlockHeader
{
public:
    // header
    static const int CURRENT_VERSION=2;
    int nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    unsigned int nTime;
    unsigned int nBits;  // Primecoin: prime chain target, see prime.cpp
    unsigned int nNonce;

    // Primecoin: proof-of-work certificate
    // Multiplier to block hash to derive the probable prime chain (k=0, 1, ...)
    // Cunningham Chain of first kind:  hash * multiplier * 2**k - 1
    // Cunningham Chain of second kind: hash * multiplier * 2**k + 1
    // BiTwin Chain:                    hash * multiplier * 2**k +/- 1
    CBigNum bnPrimeChainMultiplier;

    CBlockHeader()
    {
        SetNull();
    }


    void SetNull()
    {
        nVersion = CBlockHeader::CURRENT_VERSION;
        hashPrevBlock = 0;
        hashMerkleRoot = 0;
        nTime = 0;
        nBits = 0;
        nNonce = 0;
        bnPrimeChainMultiplier = 0;
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }

    // Primecoin: header hash does not include prime certificate
    uint256 GetHeaderHash() const
    {
        return Hash(BEGIN(nVersion), END(nNonce));
    }

    // Primecoin: block hash includes prime certificate
    uint256 GetHash() const
    {
        CDataStream ss(SER_GETHASH, 0);
        ss << nVersion << hashPrevBlock << hashMerkleRoot << nTime << nBits << nNonce << bnPrimeChainMultiplier;
        return Hash(ss.begin(), ss.end());
    }

};

class CBlock : public CBlockHeader
{
public:
    // network and disk
    unsigned int nPrimeChainType;   // primecoin: chain type (memory-only)
    unsigned int nPrimeChainLength; // primecoin: chain length (memory-only)

    CBlock()
    {
        SetNull();
    }

    CBlock(const CBlockHeader &header)
    {
        SetNull();
        *((CBlockHeader*)this) = header;
    }

    void SetNull()
    {
        CBlockHeader::SetNull();
        nPrimeChainType = 0;
        nPrimeChainLength = 0;
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
        return block;
    }

    void print() const
    {
        printf("CBlock(hash=%s, hashBlockHeader=%s, ver=%d, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u )\n",
            GetHash().ToString().c_str(),
            GetHeaderHash().ToString().c_str(),
            nVersion,
            hashPrevBlock.ToString().c_str(),
            hashMerkleRoot.ToString().c_str(),
            nTime, nBits, nNonce
            );
        
    }


};

class CBlockIndex {
};

#endif



