// https://github.com/wumansgy/goEncrypt
// https://github.com/thinkoner/openssl
package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"math/big"

	"windzhu0514/go-utils/crypto/ecbcipher"
)

const (
	ModeECB = 1 << iota
	ModeCBC
	ModePCBC
	ModeCFB
	ModeOFB
	ModeCTR
	PaddingNo
	PaddingBit
	PaddingPKCS7 // 等同于PaddingPKCS5
	PaddingZero
)

// pkcs5作为pkcs7的子集算法，使用上没有什么区别，只是在blockSize上固定为 8 bytes，即数据始终会被切割成 8 个字节的数据块，然后计算需要填充的长度。pkcs7的填充长度blockSize是 1~255 bytes

// PKCS5与PKCS7的区别：PKCS5用于块大小8Byte PKCS7用于块大小1-255Byte
// https://en.wikipedia.org/wiki/Padding_%28cryptography%29#PKCS#5_and_PKCS#7
// PKCS #5:https://www.ietf.org/rfc/rfc2898.txt
// PKCS #7:https://www.ietf.org/rfc/rfc2315.txt

type PaddingMode interface {
	Padding(src []byte, blockSize int) []byte
	UnPadding(src []byte) []byte
}

type NoPadding struct{}

func (NoPadding) Padding(src []byte, blockSize int) []byte {
	return src
}

func (NoPadding) UnPadding(src []byte) []byte {
	return src
}

type PKCS7Padding struct{}

func (PKCS7Padding) Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func (PKCS7Padding) UnPadding(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}

type ZeroPadding struct{}

func (ZeroPadding) Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(0)}, padding)
	return append(src, padtext...)
}

func (ZeroPadding) UnPadding(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}

func newBlockEncrypter(b cipher.Block, iv []byte, flag int) interface{} {
	flag = flag & 0xFF
	switch flag {
	case ModeECB:
		return ecbcipher.NewECBEncrypter(b)
	case ModeCBC:
		return cipher.NewCBCEncrypter(b, iv)
	case ModePCBC:
		return nil
	case ModeCFB:
		return cipher.NewCFBEncrypter(b, iv)
	case ModeOFB:
		return cipher.NewOFB(b, iv)
	case ModeCTR:
		return cipher.NewCTR(b, iv)
	default:
		return cipher.NewCBCEncrypter(b, iv)
	}
}

func newBlockDecrypter(b cipher.Block, iv []byte, flag int) interface{} {
	flag = flag & 0xFF
	switch flag {
	case ModeECB:
		return ecbcipher.NewECBDecrypter(b)
	case ModeCBC:
		return cipher.NewCBCDecrypter(b, iv)
	case ModePCBC:
		return nil
	case ModeCFB:
		return cipher.NewCFBDecrypter(b, iv)
	case ModeOFB:
		return cipher.NewOFB(b, iv)
	case ModeCTR:
		return cipher.NewCTR(b, iv)
	default:
		return cipher.NewCBCDecrypter(b, iv)
	}
}

func paddingMode(flag int) PaddingMode {
	flag = flag & 0xFF00
	switch flag {
	// case PaddingBit:
	// 	return NonePadding{}
	case PaddingPKCS7:
		return PKCS7Padding{}
	case PaddingZero:
		return ZeroPadding{}
	default:
		return NoPadding{}
	}
}

// 块加密
func blockEncrypt(block cipher.Block, plaintext, iv []byte, flag int) ([]byte, error) {
	plaintext = paddingMode(flag).Padding(plaintext, des.BlockSize)

	var ciphertext []byte
	if flag&0xFF != ModeECB {
		ciphertext = make([]byte, des.BlockSize+len(plaintext))
		if iv == nil {
			iv := ciphertext[:des.BlockSize]
			if _, err := io.ReadFull(rand.Reader, iv); err != nil {
				return nil, nil
			}
		} else {
			if len(iv) != des.BlockSize {
				return nil, errors.New("IV length must equal block size")
			}

			copy(ciphertext[:des.BlockSize], iv)
		}

	} else {
		ciphertext = make([]byte, len(plaintext))
	}

	encrypter := newBlockEncrypter(block, iv, flag)
	if blockMode, ok := encrypter.(cipher.BlockMode); ok {
		blockMode.CryptBlocks(ciphertext[des.BlockSize:], plaintext)
	}
	if stream, ok := encrypter.(cipher.Stream); ok {
		stream.XORKeyStream(ciphertext[:des.BlockSize], plaintext)
	}

	return ciphertext, nil
}

// 块解密
func blockDecrypt(block cipher.Block, ciphertext, iv []byte, flag int) ([]byte, error) {
	if flag&0xFF != ModeECB {
		if iv == nil {
			iv = ciphertext[:des.BlockSize]
			ciphertext = ciphertext[des.BlockSize:]
		}
	}

	if len(ciphertext)%des.BlockSize != 0 {
		return nil, errors.New("DesDecrypt:input not full blocks")
	}

	decrypter := newBlockDecrypter(block, iv, flag)
	if blockMode, ok := decrypter.(cipher.BlockMode); ok {
		blockMode.CryptBlocks(ciphertext, ciphertext)
	}
	if stream, ok := decrypter.(cipher.Stream); ok {
		stream.XORKeyStream(ciphertext, ciphertext)
	}

	ciphertext = paddingMode(flag).UnPadding(ciphertext)

	return ciphertext, nil
}

// DES
// 可被破解，建议使用3DES或者AES代替
// ----------------------------------------------------------------------

// DESEncrypt用于DES加密 支持的块加密模式：ECB/CBC/CFB/OFB/CTR 支持的填充模式：NonePadding/PKCS7Padding/ZeroPadding
// DESEncrypt([]byte("exampletext"),[]byte("key"),0) DES/CBC/NonePadding
// DESEncrypt([]byte("exampletext"),[]byte("key"),ModeECB|PaddingPKCS7) DES/ECB/PaddingPKCS7
func DESEncrypt(plaintext, key []byte, flag int) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return blockEncrypt(block, plaintext, nil, flag)
}

// DESDecrypt用于DES解密 支持的块加密模式：ECB/CBC/CFB/OFB/CTR 支持的填充模式：NonePadding/PKCS7Padding/ZeroPadding
// DESDecrypt([]byte("ciphertext"),[]byte("key"),0) DES/CBC/NonePadding
// DESDecrypt([]byte("ciphertext"),[]byte("key"),ModeECB|PaddingPKCS7) DES/ECB/PaddingPKCS7
func DESDecrypt(ciphertext, key []byte, flag int) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return blockDecrypt(block, ciphertext, nil, flag)
}

func DESEncryptWithIV(plaintext, key, iv []byte, flag int) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return blockEncrypt(block, plaintext, iv, flag)
}

func DESDecryptWithIV(ciphertext, key, iv []byte, flag int) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return blockDecrypt(block, ciphertext, iv, flag)
}

// TripleDESEncrypt用于3重DES加密 支持的块加密模式：ECB/CBC/CFB/OFB/CTR 支持的填充模式：NonePadding/PKCS7Padding/ZeroPadding
// TripleDESEncrypt([]byte("exampletext"),[]byte("key"),0) DES/CBC/NonePadding
// TripleDESEncrypt([]byte("exampletext"),[]byte("key"),ModeECB|PaddingPKCS7) DES/ECB/PaddingPKCS7
func TripleDESEncrypt(plaintext, key []byte, flag int) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}

	return blockEncrypt(block, plaintext, nil, flag)
}

// TripleDESDecrypt用于3重DES解密 支持的块加密模式：ECB/CBC/CFB/OFB/CTR 支持的填充模式：NonePadding/PKCS7Padding/ZeroPadding
// TripleDESDecrypt([]byte("ciphertext"),[]byte("key"),0) DES/CBC/NonePadding
// TripleDESDecrypt([]byte("ciphertext"),[]byte("key"),ModeECB|PaddingPKCS7) DES/ECB/PaddingPKCS7
func TripleDESDecrypt(ciphertext, key []byte, flag int) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}

	return blockDecrypt(block, ciphertext, nil, flag)
}

func TripleDESEncryptWithIV(plaintext, key, iv []byte, flag int) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}

	return blockEncrypt(block, plaintext, iv, flag)
}

func TripleDESDecryptWithIV(ciphertext, key, iv []byte, flag int) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}

	return blockDecrypt(block, ciphertext, iv, flag)
}

// AES
// ----------------------------------------------------------------------

// AESEncrypt用于AES加密 支持的块加密模式：ECB/CBC/CFB/OFB/CTR 支持的填充模式：NonePadding/PKCS7Padding/ZeroPadding
// AESEncrypt([]byte("exampletext"),[]byte("key"),0) AES/CBC/NonePadding
// AESEncrypt([]byte("exampletext"),[]byte("key"),ModeECB|PaddingPKCS7) AES/ECB/PaddingPKCS7
func AESEncrypt(plaintext, key []byte, flag int) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return blockEncrypt(block, plaintext, nil, flag)
}

// AESDecrypt用于AES解密 支持的块加密模式：ECB/CBC/CFB/OFB/CTR 支持的填充模式：NonePadding/PKCS7Padding/ZeroPadding
// AESDecrypt([]byte("ciphertext"),[]byte("key"),0) AES/CBC/NonePadding
// AESDecrypt([]byte("ciphertext"),[]byte("key"),ModeECB|PaddingPKCS7) AES/ECB/PaddingPKCS7
func AESDecrypt(ciphertext, key []byte, flag int) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return blockDecrypt(block, ciphertext, nil, flag)
}

func AESEncryptWithIV(plaintext, key, iv []byte, flag int) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return blockEncrypt(block, plaintext, nil, flag)
}

func AESDecryptWithIV(ciphertext, key []byte, flag int) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return blockDecrypt(block, ciphertext, nil, flag)
}

// RSAEncrypt用于RSA公钥加密
func RSAEncrypt(plaintext, publicKey []byte) ([]byte, error) {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, errors.New("public key error")
	}

	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	pub := pubInterface.(*rsa.PublicKey)
	return rsa.EncryptPKCS1v15(rand.Reader, pub, plaintext)
}

// RSADecrypt用于RSA私钥解密
func RSADecrypt(ciphertext, privateKey []byte) ([]byte, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, errors.New("private key error!")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext)
}

// RSAEncryptNoPadding RSA无填充公钥加密
func RSAEncryptNoPadding(plaintext, publicKey []byte) ([]byte, error) {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, errors.New("public key error")
	}

	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	pub := pubInterface.(*rsa.PublicKey)

	cipherText := plaintext
	m := new(big.Int).SetBytes(cipherText)
	e := big.NewInt(int64(pub.E))
	return new(big.Int).Exp(m, e, pub.N).Bytes(), nil
}

// TODO:RSADecryptNoPadding RSA无填充私钥解密
func RSADecryptNoPadding(ciphertext, privateKey []byte) ([]byte, error) {
	// block, _ := pem.Decode(privateKey)
	// if block == nil {
	// 	return nil, errors.New("private key error!")
	// }
	//
	// priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	// if err != nil {
	// 	return nil, err
	// }
	//
	return nil, nil
}
