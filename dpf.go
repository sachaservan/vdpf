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

func ClientDPFInitialize() *Dpf {
	randKey := PrfKey{}
	_, err := rand.Read(randKey[:])
	if err != nil {
		panic("Error generating prf randomness")
	}
	return &Dpf{randKey, InitDPFContext(randKey[:])}
}

func ServerDPFInitialize(key PrfKey) *Dpf {
	return &Dpf{key, InitDPFContext(key[:])}
}

func ClientVDPFInitialize() *Vdpf {
	randKey := PrfKey{}
	var randHashKeys [2]HashKey
	_, err := rand.Read(randKey[:])
	if err != nil {
		panic("Error generating randomness")
	}
	_, err = rand.Read(randHashKeys[0][:])
	if err != nil {
		panic("Error generating randomness")
	}
	_, err = rand.Read(randHashKeys[1][:])
	if err != nil {
		panic("Error generating randomness")
	}

	prfctx, hash1, hash2 := InitVDPFContext(randKey[:], randHashKeys)
	return &Vdpf{Dpf{randKey, prfctx}, randHashKeys[0], randHashKeys[1], hash1, hash2}
}

func ServerVDPFInitialize(key PrfKey, hkey1 HashKey, hkey2 HashKey) *Vdpf {
	var hashKeys [2]HashKey
	hashKeys[0] = hkey1
	hashKeys[1] = hkey2

	prfctx, hash1, hash2 := InitVDPFContext(key[:], hashKeys)
	return &Vdpf{Dpf{key, prfctx}, hkey1, hkey2, hash1, hash2}
}

func (dpf *Dpf) Free() {
	DestroyDPFContext(dpf.ctx)
}

func (vdpf *Vdpf) Free() {
	DestroyDPFContext(vdpf.ctx)
	DestroyMMOHash(vdpf.H2)
	DestroyMMOHash(vdpf.H1)
}
