package main

import (
	"bufio"
	"os"
	"fmt"
	"path/filepath"
	"io/ioutil"
	"strings"
	path2 "path"
	"kfCipher/cyperImplementations"
)

var reader = bufio.NewReader(os.Stdin)

func main() {

	fmt.Println("Please enter 1: for encryption; 2: for decryption:")
	option, _ := reader.ReadString('\n')
	option = strings.TrimSpace(option)
	if option == "1" {
		fmt.Println("1: encryption\n")
		encrypt()
	} else if option == "2" {
		fmt.Println("2: decryption\n")
		decrypt()
	}

}

func encrypt() {
	fmt.Println("Please enter key string: ")
	keyString, _ := reader.ReadString('\n')
	keyString = strings.Trim(keyString, "\n")
	fmt.Println(keyString)

	fmt.Println("Please enter to-be encrypted string: ")
	plainString, _ := reader.ReadString('\n')
	plainString = strings.Trim(plainString, "\n")
	fmt.Println(plainString)

	fmt.Println("Please enter where to save the encrypted string (e.g. /Users/fox/xxx.txt) : ")
	fileDestination, _ := reader.ReadString('\n')
	fileDestination = strings.TrimSpace(fileDestination)
	fmt.Println(fileDestination)


	fmt.Println("\n===Generating derived key===")
	key := kfCipher.ConvertPassPhrase(keyString)

	fmt.Println("\n===Starting encryption===")
	cipherText := kfCipher.CFBEncrypter(key, plainString)

	fmt.Println("\n===Decrypting to verify===")
	keyForDecryption := kfCipher.ConvertPassPhrase(keyString)
	plainStringDecrypted := kfCipher.CFBDecrypter(keyForDecryption, cipherText)

	if plainString == plainStringDecrypted {
		fmt.Println("Supplied plaintext == Decrypted plaintext")
	} else {
		panic("Supplied plaintext != Decrypted plaintext")
	}

	fmt.Println("\n===Saving ciphertext===")
	writeToFile(fileDestination, cipherText)

	fmt.Println("\n===Finished===")
}

func decrypt() {
	fmt.Println("Please enter where to find the ciphertext (e.g. /Users/fox/xxx.txt) : ")
	fileLocation, _ := reader.ReadString('\n')
	fileLocation = strings.TrimSpace(fileLocation)
	fmt.Println(fileLocation)

	fmt.Println("Please enter key string: ")
	keyString, _ := reader.ReadString('\n')
	keyString = strings.Trim(keyString, "\n")
	fmt.Println(keyString)

	fmt.Println("\n===Generating derived key===")
	key := kfCipher.ConvertPassPhrase(keyString)

	fmt.Println("\n===Reading supplied file===")
	cipherText := readFromFile(fileLocation)

	fmt.Println("\n===Start decrypting===")
	plainString := kfCipher.CFBDecrypter(key, cipherText)

	fmt.Println("\n\n==========================")
	fmt.Println("=========RESULT===========")
	fmt.Println("==========================")
	fmt.Println(plainString)
}

func isAvailableForWrite(filePath string) bool {
	if !filepath.IsAbs(filePath) {
		fmt.Println("Path supplied is not absolute.")
		return false
	}

	path := path2.Dir(filePath)
	if _, error := os.Stat(path); os.IsNotExist(error) {
		fmt.Printf("%s does not exist.\n", path)
		return false
	}

	if _, error := os.Stat(filePath); os.IsNotExist(error) {
		fmt.Printf("%s is available for saving ciphertext.\n", filePath)
	} else {
		fmt.Printf("%s already exists.\n", filePath)
		return false
	}

	return true
}

func isAvailableForRead(filePath string) bool {
	if !filepath.IsAbs(filePath) {
		fmt.Println("Path supplied is not absolute.")
		return false
	}

	if _, error := os.Stat(filePath); os.IsNotExist(error) {
		fmt.Printf("%s does not exist.\n", filePath)
		return false
	}

	return true
}

func writeToFile(filePath string, body string) {
	if !isAvailableForWrite(filePath) {
		panic("File destination is not available.")
	}

	// FileMode 0644 -> drw-r--r--
	// FileMode 0777 -> drwxrwxrwx
	ioutil.WriteFile(filePath, []byte(body), 0644)
}

func readFromFile(filePath string) string {
	if !isAvailableForRead(filePath) {
		panic("File doesn't exit.")
	}

	dat, err := ioutil.ReadFile(filePath)
	if err != nil {
		panic("Can not read file.")
	}

	body := strings.Trim(string(dat), "\n")
	fmt.Println(body)
	return body
}
