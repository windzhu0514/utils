package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"

	"github.com/satori/go.uuid"
)

// UUID 56bd51e2-fe5e-42cf-adf2-036c5e341d6c
func UUID() string {
	uuid, err := uuid.NewV4()
	if err != nil {
		return ""
	}

	return uuid.String()
}

//输入待计算的 src,返回 小写的MD5结果
func Md5String(src string) string {
	h := md5.New()
	h.Write([]byte(src))
	return hex.EncodeToString(h.Sum(nil))
}

// 获取字符串的 SHA-1 值
func SHA1Str(s string) string {
	t := sha1.New()
	t.Write([]byte(s))
	return hex.EncodeToString(t.Sum(nil))
}

// 固定的IV
var commonIV = []byte{0x5a, 0xe3, 0xf0, 0x46, 0xcc, 0x11, 0xb4, 0x45, 0x09, 0x04, 0x47, 0x58, 0x00, 0xbf, 0x88, 0xd5}

func AESEncrypt(src, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	src = PKCS7Padding(src, block.BlockSize())
	dst := make([]byte, len(src))
	blockMode := cipher.NewCBCEncrypter(block, commonIV)
	blockMode.CryptBlocks(dst, src)

	return dst, nil
}

func AESDecrypt(src, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	dst := make([]byte, len(src))
	blockMode := cipher.NewCBCDecrypter(block, commonIV)
	if len(src)%blockMode.BlockSize() != 0 {
		return nil, errors.New("crypto/cipher: input not full blocks")
	}

	blockMode.CryptBlocks(dst, src)
	dst = PKCS7UnPadding(dst)

	return dst, nil
}

// PKCS7Padding 和 PKCS5Padding 填充方式一样
// PKCS7Pad() pads an byte array to be a multiple of 16
// http://tools.ietf.org/html/rfc5652#section-6.3
func PKCS7Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

// PKCS7UnPadding 和 PKCS5UnPadding 去填充方式一样
// PKCS7Unpad() removes any potential PKCS7 padding added.
func PKCS7UnPadding(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}

// des加密
func DesEncrypt(origData, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	origData = PKCS5Padding(origData, block.BlockSize())
	// origData = ZeroPadding(origData, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, key)
	crypted := make([]byte, len(origData))
	// 根据CryptBlocks方法的说明，如下方式初始化crypted也可以
	// crypted := origData
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

//des解密
func DesDecrypt(crypted, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, key)
	if len(crypted)%blockMode.BlockSize() != 0 {
		return nil, errors.New("crypto/cipher: input not full blocks")
	}
	//origData := make([]byte, len(crypted))
	origData := crypted
	blockMode.CryptBlocks(origData, crypted)
	//origData = PKCS5UnPadding(origData)

	origData = PKCS5UnPadding(origData)
	return origData, nil
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

// Rsa 加密
func RsaEncrypt(origData, publicKey []byte) ([]byte, error) {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, errors.New("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub := pubInterface.(*rsa.PublicKey)
	return rsa.EncryptPKCS1v15(rand.Reader, pub, origData)
}

// Rsa 解密
func RsaDecrypt(ciphertext, privateKey []byte) ([]byte, error) {
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
