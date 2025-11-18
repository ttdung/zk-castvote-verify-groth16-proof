package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"example/anonymousvote/utils"

	// "strings"
	"bytes"
)

func mysha256(input []byte) [32]byte {
	var hash [32]byte
	// Calculate SHA-256 hash
	hash = sha256.Sum256(input)
	return hash
}

func verifyEncryptedDataIntegrity(journal string, ciphertext string, aad string) bool {

	// Extract cipherHashCode from journal
	l := len(journal)
	cipherHashCode := journal[(l - 64):]

	decodeCipherHashCode, err := hex.DecodeString(cipherHashCode)
	if err != nil {
		fmt.Println(err)
		return false
	}

	ct, err := hex.DecodeString(ciphertext)
	if err != nil {
		return false
	}

	input := append([]byte(aad), ct...)
	cipherHash := mysha256(input)

	// debug
	fmt.Println("decodeCipherHashCode: ", decodeCipherHashCode)
	fmt.Println("cipherHash: ", cipherHash)

	if bytes.Equal(decodeCipherHashCode[:], cipherHash[:]) {
		fmt.Println("data1 is equal to data2")
		return true
	} else {
		fmt.Println("data1 is not equal to data2")
		return false
	}

	return true
}


func main() {
	vote := &utils.VoteRequest{
		Seal: "73c457ba10a3ca651f6d58af20241ac344ae75a4c85d29db862ecf36d8f419a16d2efd711c8f382af116509c9f334f622ebc206f8c8254d8529ec8cf12a598b6b7a3f9eb0f1eef2699d7079614efbef31d95cae4793909ef4ea90b74bfc7759a170cae7d2327c229d5e4f94c94f5c4de2371c9d26c93b682d2502ed86c10f9403af3c2092b621cdd802d4bf42a9e0f3db98c243743c11b9e2fe3f4bd7c44a48545b3feff2cf26b2ca7eca2b5b3777ce21b50b9b6f20e2b546914ca5f7ebfee50c3d0c4a7132368a23f4155e5a7aec6abcd61e3a26a3722c6f31e19adfb582ba2d081d00e0137d0aefefe6b68c7630d4f4564517cf151f5b2d57a42042051337250499738",
		Journal: "000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000654000000000000000396139646530323734333434313164353865353235353264643362663731633262373562323735303332363332393339363237616664383565343031306238341e00000001e90300000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000",
		JournalAbi: "4000000000000000396139646530323734333434313164353865353235353264643362663731633262373562323735303332363332393339363237616664383565343031306238341e00000001e90300000000000000000000000000000100000000000000",
		ImageID: "43706d1c05d8ab2375026a165aca9e5d2cf2123ff77a40438580c47e6f968861",
		Nullifier: "0x0000000000000000000000000000000000000000000000000000000000000000",
		Age: 35,
		IsStudent: false,
		PollID: 0,
		OptionA: 1,
		OptionB: 0,
	}

	result, err := utils.Checkvote(vote)
	if err != nil {
		fmt.Println("Error: ", err)
	} else {
		fmt.Println("Vote is valid")
		fmt.Println("Vote: ", result)
	}
}