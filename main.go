package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
)

func main() {
	src := "aestext"
	key := "5c33tE2ah*4sM5cs"
	iv := "e@45*t8bzsUFdg9s"
	enText := En(src, key, iv)
	fmt.Println("enText:", enText)

	sourText := UnEn(enText, key, iv)
	fmt.Println("sourText:", sourText)
}

//加密
func En(src string, srckey string, iv string) string {
	key := []byte(paddingkey(srckey))
	result, err := aesEncrypt([]byte(src), []byte(key), []byte(iv))
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(result)
}

//解密
func UnEn(src string, srckey string, iv string) string {

	key := []byte(paddingkey(srckey))

	var result []byte
	var err error

	result, err = base64.StdEncoding.DecodeString(src)
	if err != nil {
		panic(err)
	}
	origData, err := aesDecrypt(result, []byte(key), []byte(iv))
	if err != nil {
		panic(err)
	}
	return string(origData)

}
func aesEncrypt(origData, key []byte, IV []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	origData = pKCS5Padding(origData, blockSize)
	// origData = ZeroPadding(origData, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, IV[:blockSize])
	crypted := make([]byte, len(origData))
	// 根据CryptBlocks方法的说明，如下方式初始化crypted也可以
	// crypted := origData
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

func aesDecrypt(crypted, key []byte, IV []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, IV[:blockSize])
	origData := make([]byte, len(crypted))
	// origData := crypted
	blockMode.CryptBlocks(origData, crypted)
	origData = pKCS5UnPadding(origData)
	// origData = ZeroUnPadding(origData)
	return origData, nil
}

func pKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func pKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	// 去掉最后一个字节 unpadding 次
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

//填充
func paddingkey(key string) string {
	var buffer bytes.Buffer
	buffer.WriteString(key)

	for i := len(key); i < 16; i++ {
		buffer.WriteString("0")
	}

	return buffer.String()
}
