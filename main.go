package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"math/rand"
	"time"
)

var length, count = 25, 10

var secret = make([]byte, 32)

var keyboard = []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "0", "-", "=", "q", "w", "e", "r", "t", "y", "u", "i", "o", "p", "[", "]", "\\", "a", "s", "d", "f", "g", "h", "j", "k", "l", ";", "'", "z", "x", "c", "v", "b", "n", "m", ",", ".", "/", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "@", "#", "$", "%", "&", "+"}

func main() {
	rand.Seed(time.Now().UnixNano())
	if _, err := rand.Read(secret); err != nil {
		panic(err)
	}

	result := make([]string, 0)
	channels := make([]chan string, count)

	for i := 0; i < count; i++ {
		channels[i] = make(chan string)
	}

	start := time.Now()
	for i := 0; i < count; i++ {
		go genPass(channels[i])
	}
	for i := 0; i < count; i++ {
		result = append(result, <-channels[i])
	}
	for i := 0; i < count; i++ {
		fmt.Println(fmt.Sprintf("%d len-%d result: %s", i+1, len(result[i]), result[i]))
	}
	fmt.Println("Execution time:", time.Since(start))
	fmt.Println("Decrypted:")
	for i, v := range result {
		res, err := decryptString(secret, v)
		if err != nil {
			panic(err)
		}
		fmt.Println(fmt.Sprintf("%d len-%d result: %s", i+1, len(res), res))
	}
}

func genPass(res chan string) {
	var password string
	for i := 0; i < length; i++ {
		password += keyboard[rand.Intn(len(keyboard)-1)+1]
	}
	encrypted, err := encryptString(secret, password)
	if err != nil {
		panic(err)
	}
	res <- encrypted
}

func encryptString(key []byte, plaintext string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	plaintextBytes := []byte(plaintext)
	paddedPlaintext := addPadding(plaintextBytes, block.BlockSize())

	iv := make([]byte, block.BlockSize())
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(paddedPlaintext))
	mode.CryptBlocks(ciphertext, paddedPlaintext)

	ciphertext = append(iv, ciphertext...)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decryptString(key []byte, ciphertext string) (string, error) {
	ciphertextBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	iv := ciphertextBytes[:block.BlockSize()]
	ciphertextBytes = ciphertextBytes[block.BlockSize():]

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertextBytes))
	mode.CryptBlocks(plaintext, ciphertextBytes)

	plaintext = removePadding(plaintext)

	return string(plaintext), nil
}

func addPadding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padText...)
}

func removePadding(src []byte) []byte {
	padding := src[len(src)-1]
	return src[:len(src)-int(padding)]
}
