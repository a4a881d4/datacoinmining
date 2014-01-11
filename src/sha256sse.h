#ifndef __SHA256SSE_H
#define __SHA256SSE_H
#pragma pack(push,1)
struct work {
	char pdata[128];
	char phash[32];
	uint32_t max_nonce;
	uint32_t target;
	uint64_t mulfactor;
	uint64_t nHashesDone;
};
#pragma pack(pop)

extern "C" int scanhash_sse2_64( const void *pWork );

#endif
