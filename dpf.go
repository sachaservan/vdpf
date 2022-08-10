package dpf

import "crypto/rand"

type PrfKey [16]byte
type HashKey [16]byte

type DPFKey struct {
	Bytes     []byte
	RangeSize uint
	Index     uint64
}

type Dpf struct {
	PrfKey PrfKey
	ctx    PrfCtx
}

type Vdpf struct {
	Dpf
	H1Key HashKey
	H2Key HashKey
	H1    Hash
	H2    Hash
}

func ClientDPFInitialize(prfKey PrfKey) *Dpf {
	return &Dpf{prfKey, InitDPFContext(prfKey[:])}
}

func ServerDPFInitialize(key PrfKey) *Dpf {
	return &Dpf{key, InitDPFContext(key[:])}
}

func GenerateVDPFHashKeys() [2]HashKey {
	var hashKeys [2]HashKey

	_, err := rand.Read(hashKeys[0][:])
	if err != nil {
		panic("Error generating randomness")
	}
	_, err = rand.Read(hashKeys[1][:])
	if err != nil {
		panic("Error generating randomness")
	}

	return hashKeys
}

func GeneratePRFKey() PrfKey {
	randKey := PrfKey{}
	_, err := rand.Read(randKey[:])
	if err != nil {
		panic("Error generating randomness")
	}
	return randKey
}

func ClientVDPFInitialize(prfKey PrfKey, hashKeys [2]HashKey) *Vdpf {

	prfctx, hash1, hash2 := InitVDPFContext(prfKey[:], hashKeys)
	return &Vdpf{Dpf{prfKey, prfctx}, hashKeys[0], hashKeys[1], hash1, hash2}
}

func ServerVDPFInitialize(key PrfKey, hashKeys [2]HashKey) *Vdpf {

	prfctx, hash1, hash2 := InitVDPFContext(key[:], hashKeys)
	return &Vdpf{Dpf{key, prfctx}, hashKeys[0], hashKeys[1], hash1, hash2}
}

func (dpf *Dpf) Free() {
	DestroyDPFContext(dpf.ctx)
}

func (vdpf *Vdpf) Free() {
	DestroyDPFContext(vdpf.ctx)
	DestroyMMOHash(vdpf.H2)
	DestroyMMOHash(vdpf.H1)
}
