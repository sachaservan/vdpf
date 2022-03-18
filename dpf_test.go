package dpf

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"
)

const numTrials = 100

func TestCorrectPointFunctionTwoServer(t *testing.T) {

	for trial := 0; trial < numTrials; trial++ {
		num := 1 << 15

		specialIndex := uint64(rand.Intn(num))

		// generate fss Keys on client
		client := ClientDPFInitialize()

		// fmt.Printf("index  %v\n", specialIndex)
		keyA, keyB := client.GenDPFKeys(specialIndex, 64)

		// simulate the server
		server := ServerDPFInitialize(client.PrfKey)

		indices := make([]uint64, num)
		for i := 0; i < num; i++ {
			indices[i] = uint64(rand.Intn(num))
		}
		ans0 := server.BatchEval(keyA, indices)
		ans1 := server.BatchEval(keyB, indices)

		// fmt.Printf("ans0 = %v\n", ans0)
		// fmt.Printf("ans1 = %v\n", ans1)
		for i := 0; i < num; i++ {

			// fmt.Printf("ans0 = %v\n", ans0[i])
			// fmt.Printf("ans1 = %v\n", ans1[i])

			sum := ans0[i] ^ ans1[i]

			if uint64(indices[i]) == specialIndex && uint(sum) != 1 {
				t.Fatalf("Expected: %v Got: %v", 1, sum)
			}

			if uint64(indices[i]) != specialIndex && sum != 0 {
				t.Fatalf("Expected: 0 Got: %v", sum)
			}
		}
	}
}

func TestCorrectPointFunctionTwoServerFullDomain(t *testing.T) {

	for trial := 0; trial < numTrials; trial++ {

		num := 1 << 15
		specialIndex := uint64(rand.Intn(num))

		// generate fss Keys on client
		client := ClientDPFInitialize()

		// fmt.Printf("index  %v\n", specialIndex)
		keyA, keyB := client.GenDPFKeys(specialIndex, 15)

		// fmt.Printf("keyA = %v\n", keyA)
		// fmt.Printf("keyB = %v\n", keyB)

		// simulate the server
		server := ServerDPFInitialize(client.PrfKey)

		ans0 := server.FullDomainEval(keyA)
		ans1 := server.FullDomainEval(keyB)

		// fmt.Printf("ans0 = %v\n", ans0)
		// fmt.Printf("ans1 = %v\n", ans1)
		for i := 0; i < num; i++ {

			// fmt.Printf("ans0 = %v\n", ans0[i])
			// fmt.Printf("ans1 = %v\n", ans1[i])

			sum := ans0[i] ^ ans1[i]

			if uint64(i) == specialIndex && uint(sum) != 1 {
				t.Fatalf("Expected: %v Got: %v", 1, sum)
			}

			if uint64(i) != specialIndex && sum != 0 {
				t.Fatalf("Expected: 0 Got: %v", sum)
			}
		}
	}
}

func TestCorrectVerifiablePointFunctionTwoServer(t *testing.T) {

	for trial := 0; trial < numTrials; trial++ {
		num := rand.Intn(1 << 15)

		specialIndex := uint64(rand.Intn(num))

		// generate fss Keys on client
		client := ClientVDPFInitialize()

		// fmt.Printf("index  %v\n", specialIndex)
		keyA, keyB := client.GenVDPFKeys(specialIndex, 64)

		// fmt.Printf("keyA = %v\n", keyA)
		// fmt.Printf("keyB = %v\n", keyB)

		// simulate the server
		server := ServerVDPFInitialize(client.PrfKey, client.H1Key, client.H2Key)

		indices := make([]uint64, num)
		for i := 0; i < num; i++ {
			indices[i] = uint64(rand.Intn(num))
		}
		ans0, pi0 := server.BatchVerEval(keyA, indices)
		ans1, pi1 := server.BatchVerEval(keyB, indices)

		if !bytes.Equal(pi0, pi1) {
			fmt.Println()
			t.Fatalf("pi0 =/= p1\n%v\n%v\n", pi0, pi1)
		}

		for i := 0; i < num; i++ {

			// fmt.Printf("ans0 = %v\n", ans0)
			// fmt.Printf("ans1 = %v\n", ans1)

			sum := ans0[i] ^ ans1[i]

			if uint64(indices[i]) == specialIndex && sum != 1 {
				t.Fatalf("Expected: %v Got: %v", 1, sum)
			}

			if uint64(indices[i]) != specialIndex && sum != 0 {
				t.Fatalf("Expected: 0 Got: %v", sum)
			}
		}
	}
}

func Benchmark2PartyServerInit(b *testing.B) {

	fClient := ClientDPFInitialize()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		ServerDPFInitialize(fClient.PrfKey)
	}
}

func Benchmark2Party64BitKeywordEval(b *testing.B) {

	client := ClientDPFInitialize()
	keyA, _ := client.GenDPFKeys(1, 64)
	server := ServerDPFInitialize(client.PrfKey)

	indices := make([]uint64, 1)
	indices[0] = 1

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		server.BatchEval(keyA, indices)
	}
}

func Benchmark2PartyFullDomainEval(b *testing.B) {

	client := ClientDPFInitialize()
	keyA, _ := client.GenDPFKeys(1, 20)
	server := ServerDPFInitialize(client.PrfKey)

	indices := make([]uint64, 1)
	indices[0] = 1

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		server.FullDomainEval(keyA)
	}
}

func Benchmark2Party64BitVerifiableKeywordEval(b *testing.B) {

	client := ClientVDPFInitialize()
	keyA, _ := client.GenDPFKeys(1, 64)
	server := ServerVDPFInitialize(client.PrfKey, client.H1Key, client.H2Key)

	indices := make([]uint64, 1)
	indices[0] = 1

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		server.BatchVerEval(keyA, indices)
	}
}

func BenchmarkDPFGen(b *testing.B) {

	b.ResetTimer()

	for i := 0; i < b.N; i++ {

		client := ClientDPFInitialize()
		client.GenDPFKeys(1, 64)
		DestroyDPFContext(client.ctx)
	}
}
