package kfCipher

import (
	"fmt"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"crypto/rand"
	"io"
)


func CFBEncrypter(key []byte, plainString string) string {
	//if len(key) != 16 || len(key) != 24 || len(key) !=32 {
	//	panic("The key argument should be the AES key, either 16, 24, or 32 bytes to select AES-128, AES-192, or AES-256.")
	//}
	plaintext := []byte(plainString)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	cipherString := fmt.Sprintf("%x\n", ciphertext)
	fmt.Print("Ciper String: ")
	fmt.Print(cipherString)
	return cipherString
}

func CFBDecrypter(key []byte, cipherString string) string {
	//if len(key) != 16 || len(key) != 24 || len(key) !=32 {
	//	panic("The key argument should be the AES key, either 16, 24, or 32 bytes to select AES-128, AES-192, or AES-256.")
	//}
	ciphertext, _ := hex.DecodeString(cipherString)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(ciphertext, ciphertext)
	fmt.Print("Cipher string decrypted: ")
	fmt.Printf("%s \n", ciphertext)
	return string(ciphertext)
}

func ConvertPassPhrase(passPhrase string) []byte {
	key := []byte(passPhrase)
	fmt.Println("key entered: ", passPhrase)
	fmt.Println("key has ", len(key), " byte")

	// derived key contains 32 bytes (256 bits, 8*numOfCharInStringGoLang , 32)
	var dk [32]byte
	copy(dk[:], key)

	fmt.Println("key in byte: ", key)
	fmt.Println("derived key in byte: ", dk)


	return dk[:]
}