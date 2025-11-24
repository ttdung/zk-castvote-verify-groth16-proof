package utils


import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"

	"example/anonymousvote/groth16"
	"github.com/datachainlab/go-risc0-verifier/risc0"

	// "strings"
	"bytes"
)

type VoteResponse struct {
	Nullifier string
	Age       uint32
	IsStudent bool
	PollID    uint64
}

type VoteRequest struct {
	Seal 	 string `json:"seal"`
	Journal 	string `json:"journal"`
	JournalAbi string `json:"journal_abi"`
	ImageID     string `json:"image_id"`
	Nullifier string `json:"nullifier"`
	Age       uint32 `json:"age"`
	IsStudent bool `json:"is_student"`
	PollID    uint64 `json:"poll_id"`
}

func decodeBincodeVote(data []byte) (*VoteResponse, error) {
	buf := bytes.NewReader(data)

	// Read string length (bincode uses u64 for length prefix)
	var strLen uint64
	if err := binary.Read(buf, binary.LittleEndian, &strLen); err != nil {
		return nil, err
	}

	strBytes := make([]byte, strLen)
	if _, err := buf.Read(strBytes); err != nil {
		return nil, err
	}
	nullifier := string(strBytes)

	var age uint32
	if err := binary.Read(buf, binary.LittleEndian, &age); err != nil {
		return nil, err
	}

	var isStudent byte
	if err := binary.Read(buf, binary.LittleEndian, &isStudent); err != nil {
		return nil, err
	}

	var pollID uint64
	if err := binary.Read(buf, binary.LittleEndian, &pollID); err != nil {
		return nil, err
	}

	return &VoteResponse{
		Nullifier: nullifier,
		Age:       age,
		IsStudent: isStudent != 0,
		PollID:    pollID,
	}, nil

}

func Checkvote(vote *VoteRequest) (*VoteResponse, error) {
	var imageID [32]byte
	// imageID_, err := hex.DecodeString("43706d1c05d8ab2375026a165aca9e5d2cf2123ff77a40438580c47e6f968861")
	imageID_, err := hex.DecodeString(vote.ImageID)
	if err != nil {
		fmt.Println("Failed to decode imageID: ", err)
		return nil, err
	}
	copy(imageID[:], imageID_)

	// journal, err := hex.DecodeString("000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000654000000000000000396139646530323734333434313164353865353235353264643362663731633262373562323735303332363332393339363237616664383565343031306238341e00000001e90300000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000")
	journal, err := hex.DecodeString(vote.Journal)
	if err != nil {
		fmt.Println("Failed to decode journal: ", err)
		return nil, err
	}
	journalDigest := mysha256(journal)
	claimDigest := risc0.CalculateClaimDigest(imageID, journalDigest)

	fmt.Println("claimDigest:", claimDigest)

	// seal, err := hex.DecodeString("73c457ba10a3ca651f6d58af20241ac344ae75a4c85d29db862ecf36d8f419a16d2efd711c8f382af116509c9f334f622ebc206f8c8254d8529ec8cf12a598b6b7a3f9eb0f1eef2699d7079614efbef31d95cae4793909ef4ea90b74bfc7759a170cae7d2327c229d5e4f94c94f5c4de2371c9d26c93b682d2502ed86c10f9403af3c2092b621cdd802d4bf42a9e0f3db98c243743c11b9e2fe3f4bd7c44a48545b3feff2cf26b2ca7eca2b5b3777ce21b50b9b6f20e2b546914ca5f7ebfee50c3d0c4a7132368a23f4155e5a7aec6abcd61e3a26a3722c6f31e19adfb582ba2d081d00e0137d0aefefe6b68c7630d4f4564517cf151f5b2d57a42042051337250499738")

	seal, err := hex.DecodeString(vote.Seal)
	if err != nil {
		fmt.Println("Failed to decode seal: ", err)
		return nil, err
	}

	p, ok := groth16.GetVerifierParameters2(seal[:4])
	if !ok {
		fmt.Println("GetVerifierParameters2 failed")
		return nil, err
	}

	err = groth16.VerifyIntegrity(p, seal[4:], claimDigest)
	if err != nil {
		fmt.Println(err)
		return nil, err
	} else {
		fmt.Println("verify OK!")
	}

	// Replace this with the actual journal abi decode from Rust
	// cleanHexString := "4000000000000000396139646530323734333434313164353865353235353264643362663731633262373562323735303332363332393339363237616664383565343031306238341e00000001e90300000000000000000000000000000100000000000000"
	cleanHexString := vote.JournalAbi
	data, err := hex.DecodeString(cleanHexString)
	if err != nil {
		log.Fatalf("Failed to decode hex string: %v", err)
		return nil, err
	}

	voteResponse, err := decodeBincodeVote(data)
	if err != nil {
		log.Fatalf("Failed to decode hex string: %v", err)
		return nil, err
	}

	fmt.Printf("Decoded Vote: %+v\n", voteResponse)
	fmt.Printf("Poll ID: %v\n", vote.PollID)

	return voteResponse, nil
}

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
