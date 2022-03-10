package dpf

// Testing in C the time goes from 7 to 4 seconds for 1000000 with the O3 flag
// Since cgo removes all optimization flags we first compile a (optimized)
// static library and then link it.
// Simon Langowski spent many hours debugging this.

// #cgo CFLAGS: -I${SRCDIR}/include
// #cgo LDFLAGS: ${SRCDIR}/src/libdpf.a -lcrypto -lssl -lm
// #include "dpf.h"
// #include "mmo.h"
import "C"
import (
	"unsafe"
)

var HASH1BLOCKOUT uint = 4
var HASH2BLOCKOUT uint = 2

type PrfCtx *C.struct_evp_cipher_ctx_st
type Hash *C.struct_Hash

func NewDPFKey(bytes []byte, rangeSize uint, index uint64) *DPFKey {
	return &DPFKey{bytes, rangeSize, index}
}

func getRequiredKeySize(rangeSize uint) uint {
	// this is the required key size for the VDPF
	// so we overallocate for the DPF
	// TODO: this is all super hacky. Would be nice
	// to patch this up.
	return 18*rangeSize + 18 + 16 + 16*4
}

func InitDPFContext(prfKey []byte) PrfCtx {
	if len(prfKey) != 16 {
		panic("bad prf key size")
	}

	p := C.getDPFContext((*C.uchar)(unsafe.Pointer(&prfKey[0])))
	return p
}

func InitVDPFContext(prfKey []byte, hashkeys [2]HashKey) (PrfCtx, Hash, Hash) {

	p := InitDPFContext(prfKey)

	hash1 := C.initMMOHash((*C.uchar)(unsafe.Pointer(&hashkeys[0])), C.uint64_t(HASH1BLOCKOUT))
	hash2 := C.initMMOHash((*C.uchar)(unsafe.Pointer(&hashkeys[1])), C.uint64_t(HASH2BLOCKOUT))

	return p, hash1, hash2
}

func DestroyDPFContext(ctx PrfCtx) {
	C.destroyContext(ctx)
}

func DestroyMMOHash(hash Hash) {
	C.destroyMMOHash(hash)
}

func (dpf *Dpf) GenDPFKeys(specialIndex uint64, rangeSize uint) (*DPFKey, *DPFKey) {

	keySize := getRequiredKeySize(rangeSize)
	k0 := make([]byte, keySize)
	k1 := make([]byte, keySize)

	C.genDPF(
		dpf.ctx,
		C.int(rangeSize),
		C.uint64_t(specialIndex),
		(*C.uchar)(unsafe.Pointer(&k0[0])),
		(*C.uchar)(unsafe.Pointer(&k1[0])),
	)

	return NewDPFKey(k0, rangeSize, 0), NewDPFKey(k1, rangeSize, 1)
}

func (vdpf *Vdpf) GenVDPFKeys(specialIndex uint64, rangeSize uint) (*DPFKey, *DPFKey) {

	keySize := getRequiredKeySize(rangeSize)
	k0 := make([]byte, keySize)
	k1 := make([]byte, keySize)

	C.genVDPF(
		vdpf.ctx,
		vdpf.H1,
		C.int(rangeSize),
		C.uint64_t(specialIndex),
		(*C.uchar)(unsafe.Pointer(&k0[0])),
		(*C.uchar)(unsafe.Pointer(&k1[0])),
	)

	return NewDPFKey(k0, rangeSize, 0), NewDPFKey(k1, rangeSize, 1)
}

func (dpf *Dpf) BatchEval(key *DPFKey, indices []uint64) []byte {

	keySize := getRequiredKeySize(key.RangeSize)
	if len(key.Bytes) != int(keySize) {
		panic("invalid key size")
	}

	res := make([]uint64, len(indices)*2) // returned output is uint128_t
	resBytes := make([]byte, len(indices))

	C.batchEvalDPF(
		dpf.ctx,
		C.int(key.RangeSize),
		C.bool(key.Index == 1),
		(*C.uchar)(unsafe.Pointer(&key.Bytes[0])),
		(*C.uint64_t)(unsafe.Pointer(&indices[0])),
		C.uint64_t(len(indices)),
		(*C.uint8_t)(unsafe.Pointer(&res[0])),
	)

	// skip two uint64 blocks at a time
	b := 0
	for i := 0; i < len(res); i += 2 {
		resBytes[b] = byte(res[i] & 1)
		b++
	}

	return resBytes

}

func (vdpf *Vdpf) BatchVerEval(key *DPFKey, indices []uint64) ([]byte, []byte) {
	// 	extern void genVDPF(EVP_CIPHER_CTX *ctx, struct Hash *hash0, int size, uint64_t index, unsigned char* k0, unsigned char *k1);
	// extern void batchEvalVDPF(EVP_CIPHER_CTX *ctx, struct Hash *hash1, struct Hash *hash2, int size, bool b, unsigned char* k, uint64_t *in, size_t inl, uint64_t* out, uint8_t*pi);

	keySize := getRequiredKeySize(key.RangeSize)
	if len(key.Bytes) != int(keySize) {
		panic("invalid key size")
	}

	pi := make([]byte, 16*vdpf.H1.outblocks)

	res := make([]uint64, len(indices)*2) // returned output is uint128_t
	resBytes := make([]byte, len(indices))

	C.batchEvalVDPF(
		vdpf.ctx,
		vdpf.H1,
		vdpf.H2,
		C.int(key.RangeSize),
		C.bool(key.Index == 1),
		(*C.uchar)(unsafe.Pointer(&key.Bytes[0])),
		(*C.uint64_t)(unsafe.Pointer(&indices[0])),
		C.uint64_t(len(indices)),
		(*C.uint8_t)(unsafe.Pointer(&res[0])),
		(*C.uint8_t)(unsafe.Pointer(&pi[0])),
	)

	// skip two uint64 blocks at a time
	b := 0
	for i := 0; i < len(res); i += 2 {
		resBytes[b] = byte(res[i] & 1)
		b++
	}

	return resBytes, pi
}

func (dpf *Dpf) FullDomainEval(key *DPFKey) []byte {

	if key.RangeSize > 32 {
		panic("range size is too big for full domain evaluation")
	}

	keySize := getRequiredKeySize(key.RangeSize)
	if len(key.Bytes) != int(keySize) {
		panic("invalid key size")
	}

	// extern void batchEvalDPF(EVP_CIPHER_CTX *ctx, int size, bool b, unsigned char* k, uint64_t *in, size_t inl, uint64_t* out);

	resSize := 1 << key.RangeSize

	res := make([]uint64, resSize*2) // returned output is uint128_t
	resBytes := make([]byte, resSize)

	C.fullDomainDPF(
		dpf.ctx,
		C.int(key.RangeSize),
		C.bool(key.Index == 1),
		(*C.uint8_t)(unsafe.Pointer(&key.Bytes[0])),
		(*C.uint8_t)(unsafe.Pointer(&res[0])),
	)

	// skip two uint64 blocks at a time
	b := 0
	for i := 0; i < len(res); i += 2 {
		resBytes[b] = byte(res[i] & 1)
		b++
	}

	return resBytes

}

func (vdpf *Vdpf) FullDomainVerEval(key *DPFKey) ([]byte, []byte) {

	if key.RangeSize > 32 {
		panic("range size is too big for full domain evaluation")
	}

	keySize := getRequiredKeySize(key.RangeSize)
	if len(key.Bytes) != int(keySize) {
		panic("invalid key size")
	}

	resSize := 1 << key.RangeSize
	pi := make([]byte, 64)

	res := make([]uint64, resSize*2) // returned output is uint128_t
	resBytes := make([]byte, resSize)

	C.fullDomainVDPF(
		vdpf.ctx,
		vdpf.H1,
		vdpf.H2,
		C.int(key.RangeSize),
		C.bool(key.Index == 1),
		(*C.uchar)(unsafe.Pointer(&key.Bytes[0])),
		(*C.uint8_t)(unsafe.Pointer(&res[0])),
		(*C.uint8_t)(unsafe.Pointer(&pi[0])),
	)

	// skip two uint64 blocks at a time
	b := 0
	for i := 0; i < resSize; i += 2 {
		resBytes[b] = byte(res[i] & 1)
		b++
	}
	return resBytes, pi
}
