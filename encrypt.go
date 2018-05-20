package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"kfCipher/cyperImplementations"
	"os"
	path2 "path"
	"path/filepath"
	"strings"
	"flag"
)

var reader = bufio.NewReader(os.Stdin)

// command line arguments
// mode
var mode = flag.String("mode", "", "Mode of program. either encrypt or decrypt.")

// private key
var privateKeyPath = flag.String("privateKeyPath", "", "Path to a private key.")

// cypherText path
var cypherTextWritePath = flag.String("cypherTextWritePath", "", "Path to the write encrypted cyper text to file.")
var cypherTextReadPath = flag.String("cypherTextReadPath", "", "Path to read encrypted cyper text from file.")

// plaintext path
var plainTextWritePath = flag.String("plainTextWritePath", "", "Path to write plain text when decrypting.")
var plainTextReadPath = flag.String("plainTextReadPath", "", "Path to read plain text when encrypting.")

func main() {
	flag.Parse()
	fmt.Println("mode :" + *mode)
	fmt.Println("privateKeyPath :" + *privateKeyPath)
	fmt.Println("plainTextReadPath :" + *plainTextReadPath)
	fmt.Println("cypherTextWritePath :"  + *cypherTextWritePath)
	fmt.Println("cypherTextReadPath :" + *cypherTextReadPath)


	fmt.Println("Please enter 1: for encryption; 2: for decryption:")
	var option = ""
	if *mode == "" {
		option, _ = reader.ReadString('\n')
		option = strings.TrimSpace(option)
	}

	if (option == "1") || (*mode == "encrypt") {
		fmt.Println("1: encryption\n")
		encrypt()
	} else if (option == "2") || (*mode == "decrypt") {
		fmt.Println("2: decryption\n")
		decrypt()
	} else {
		fmt.Println("Unrecognized Mode. Exiting.")
	}
}

func encrypt() {
	var keyString = ""
	var plainString = ""
	var fileDestination = ""

	// Get Private Key
	if *privateKeyPath == "" {
		fmt.Println("Please enter key string: ")
		keyString, _ = reader.ReadString('\n')
	} else {
		keyStringFromFlag, _ := ioutil.ReadFile(*privateKeyPath)
		keyString = string(keyStringFromFlag)
	}
	keyString = strings.Trim(keyString, "\n")
	fmt.Println("Key String is : " + keyString)

	// Get Plain Text
	if *plainTextReadPath == "" {
		fmt.Println("Please enter to-be encrypted string: ")
		plainString, _ = reader.ReadString('\n')
	} else {
		plainStringFromFlag, _ := ioutil.ReadFile(*plainTextReadPath)
		plainString = string(plainStringFromFlag)
	}
	plainString = strings.Trim(plainString, "\n")
	fmt.Println("Plain String is : " + plainString)

	// Get CypherText output path
	if *cypherTextWritePath == "" {
		fmt.Println("Please enter where to save the encrypted string (e.g. /Users/fox/xxx.txt) : ")
		fileDestination, _ = reader.ReadString('\n')
	} else {
		fileDestination = *cypherTextWritePath
	}
	fileDestination = strings.TrimSpace(fileDestination)
	fmt.Println("File destination is : " + fileDestination)

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
	var fileLocation = ""
	// Get CyperText input path
	if *cypherTextReadPath == "" {
		fmt.Println("Please enter where to find the ciphertext (e.g. /Users/fox/xxx.txt) : ")
		fileLocation, _ = reader.ReadString('\n')
	} else {
		fileLocation = *cypherTextReadPath
	}
	fileLocation = strings.TrimSpace(fileLocation)
	fmt.Println("file location is : " + fileLocation)

	// Get Private Key
	var keyString = ""
	if *privateKeyPath == "" {
		fmt.Println("Please enter key string: ")
		keyString, _ = reader.ReadString('\n')
	} else {
		keyStringFromFile, _ := ioutil.ReadFile(*privateKeyPath)
		keyString = string(keyStringFromFile)
	}
	keyString = strings.Trim(keyString, "\n")
	fmt.Println("key string is : " + keyString)

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
