package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/windzhu0514/go-utils/crypto/ecb"
	"github.com/windzhu0514/go-utils/crypto/rsa_ext"
)

type BlockMode string

const (
	BlockModeECB = BlockMode("ECB")
	BlockModeCBC = BlockMode("CBC")
	BlockModeCFB = BlockMode("CFB")
	BlockModeCTR = BlockMode("CTR")
	BlockModeGCM = BlockMode("GCM")
	BlockModeOFB = BlockMode("OFB")
)

type Algorithm string

const (
	AlgorithmAES       = Algorithm("AES")
	AlgorithmDES       = Algorithm("DES")
	AlgorithmTripleDES = Algorithm("TripleDES")
	AlgorithmRSA       = Algorithm("RSA")
)

type PaddingMode string

const (
	PaddingModeNone  = PaddingMode("NoPadding")
	PaddingModePKCS7 = PaddingMode("PKCS7Padding")
	PaddingModeZero  = PaddingMode("ZerosPadding")
)

var (
	ErrKeyIsEmpty   = errors.New("crypto: key is empty")
	ErrIVIsEmpty    = errors.New("crypto: iv is empty")
	ErrNonceIsEmpty = errors.New("crypto: nonce is empty")
	ErrBlockMode    = errors.New("crypto: invalid block mode")
	ErrPaddingkMode = errors.New("crypto: invalid padding mode")
)

type Cipher struct {
	Algorithm      Algorithm
	BlockMode      BlockMode
	PaddingMode    PaddingMode
	Key            []byte // 对称加密Key或者公钥私钥
	IV             []byte
	Nonce          []byte
	AdditionalData []byte
	TagSize        int
}

func (c *Cipher) Encrypt(plainTxt []byte) ([]byte, error) {
	if len(c.Key) == 0 {
		return nil, ErrKeyIsEmpty
	}

	var (
		block cipher.Block
		err   error
	)

	switch c.Algorithm {
	case AlgorithmAES:
		block, err = aes.NewCipher(c.Key)
		if err != nil {
			return nil, err
		}
	case AlgorithmDES:
		block, err = des.NewCipher(c.Key)
		if err != nil {
			return nil, err
		}
	case AlgorithmTripleDES:
		block, err = des.NewTripleDESCipher(c.Key)
		if err != nil {
			return nil, fmt.Errorf("%w, TripleDES key size is 24", err)
		}
	case AlgorithmRSA:
		block, _ := pem.Decode(c.Key)
		if block == nil {
			return nil, errors.New("failed to decode PEM block")
		}

		if block.Type == "PUBLIC KEY" {
			pub, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return nil, err
			}

			return rsa.EncryptPKCS1v15(rand.Reader, pub.(*rsa.PublicKey), plainTxt)
		} else if block.Type == "PRIVATE KEY" || strings.HasSuffix(block.Type, " PRIVATE KEY") {
			priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				keyPKCS8, err := x509.ParsePKCS8PrivateKey(block.Bytes)
				if err != nil {
					return nil, err
				}

				priv = keyPKCS8.(*rsa.PrivateKey)
			}

			return rsa_ext.PrivateKeyEncrypt(rand.Reader, priv, plainTxt)
		} else if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}

			return rsa.EncryptPKCS1v15(rand.Reader, cert.PublicKey.(*rsa.PublicKey), plainTxt)
		} else {
			return nil, errors.New("invalid PEM block type")
		}

	default:
		return nil, fmt.Errorf("crypto: not supported algorithm:%s", c.Algorithm)
	}

	switch c.PaddingMode {
	case PaddingModeNone:
	case PaddingModePKCS7:
		plainTxt = PKCS7Padding{}.Padding(plainTxt, block.BlockSize())
	case PaddingModeZero:
		plainTxt = ZerosPadding{}.Padding(plainTxt, block.BlockSize())
	}

	switch c.BlockMode {
	case BlockModeECB:
		blockMode := ecb.NewECBEncrypter(block)
		dst := make([]byte, len(plainTxt))
		blockMode.CryptBlocks(dst, plainTxt)
		return dst, nil

	case BlockModeCBC:
		if len(c.IV) == 0 {
			return nil, ErrIVIsEmpty
		}

		dst := make([]byte, block.BlockSize()+len(plainTxt))
		copy(dst[:block.BlockSize()], c.IV)
		blockMode := cipher.NewCBCEncrypter(block, c.IV)
		blockMode.CryptBlocks(dst[block.BlockSize():], plainTxt)
		return dst, nil

	case BlockModeCFB:
		if len(c.IV) == 0 {
			return nil, ErrIVIsEmpty
		}

		dst := make([]byte, block.BlockSize()+len(plainTxt))
		copy(dst[:block.BlockSize()], c.IV)
		cfb := cipher.NewCFBEncrypter(block, c.IV)
		cfb.XORKeyStream(dst, plainTxt)
		return dst, nil

	case BlockModeCTR:
		if len(c.IV) == 0 {
			return nil, ErrIVIsEmpty
		}

		dst := make([]byte, block.BlockSize()+len(plainTxt))
		copy(dst[:block.BlockSize()], c.IV)
		ctr := cipher.NewCTR(block, c.IV)
		ctr.XORKeyStream(dst, plainTxt)
		return dst, nil

	case BlockModeGCM:
		if len(c.Nonce) == 0 {
			return nil, ErrNonceIsEmpty
		}

		var aesgcm cipher.AEAD
		if c.TagSize != 0 {
			aesgcm, err = cipher.NewGCMWithTagSize(block, c.TagSize)
		} else {
			aesgcm, err = cipher.NewGCMWithNonceSize(block, len(c.Nonce))
		}

		if err != nil {
			return nil, err
		}

		return aesgcm.Seal(nil, c.Nonce, plainTxt, c.AdditionalData), nil
	case BlockModeOFB:
		if len(c.IV) == 0 {
			return nil, ErrIVIsEmpty
		}
		dst := make([]byte, block.BlockSize()+len(plainTxt))
		copy(dst[:block.BlockSize()], c.IV)
		ofb := cipher.NewOFB(block, c.IV)
		ofb.XORKeyStream(plainTxt[block.BlockSize():], plainTxt)
		return dst, nil
	default:
		return nil, ErrBlockMode
	}
}

func (c *Cipher) Decrypt(cipherTxt []byte) ([]byte, error) {
	if len(c.Key) == 0 {
		return nil, ErrKeyIsEmpty
	}

	var (
		block cipher.Block
		err   error
	)

	switch c.Algorithm {
	case AlgorithmAES:
		block, err = aes.NewCipher(c.Key)
		if err != nil {
			return nil, err
		}
	case AlgorithmDES:
		block, err = des.NewCipher(c.Key)
		if err != nil {
			return nil, err
		}
	case AlgorithmTripleDES:
		block, err = des.NewTripleDESCipher(c.Key)
		if err != nil {
			return nil, fmt.Errorf("%w, TripleDES key size is 24", err)
		}
	case AlgorithmRSA:
		block, _ := pem.Decode(c.Key)
		if block == nil {
			return nil, errors.New("failed to decode PEM block")
		}

		if block.Type == "PUBLIC KEY" {
			pub, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			return rsa_ext.PublicKeyDecrypt(pub.(*rsa.PublicKey), cipherTxt)
		} else if block.Type == "PRIVATE KEY" || strings.HasSuffix(block.Type, " PRIVATE KEY") {
			priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				keyPKCS8, err := x509.ParsePKCS8PrivateKey(block.Bytes)
				if err != nil {
					return nil, err
				}

				priv = keyPKCS8.(*rsa.PrivateKey)
			}

			return rsa.DecryptPKCS1v15(rand.Reader, priv, cipherTxt)
		} else if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}

			return rsa_ext.PublicKeyDecrypt(cert.PublicKey.(*rsa.PublicKey), cipherTxt)
		} else {
			return nil, errors.New("invalid PEM block type")
		}

	default:
		return nil, fmt.Errorf("crypto: not supported algorithm:%s", c.Algorithm)
	}

	if c.BlockMode != BlockModeGCM {
		if len(cipherTxt) < block.BlockSize() {
			return nil, errors.New("input too short")
		}

		if len(cipherTxt)%block.BlockSize() != 0 {
			return nil, errors.New("input not full blocks")
		}
	}

	var dst []byte
	switch c.BlockMode {
	case BlockModeECB:
		blockMode := ecb.NewECBDecrypter(block)
		dst = make([]byte, len(cipherTxt))
		blockMode.CryptBlocks(dst, cipherTxt)

	case BlockModeCBC:
		iv := cipherTxt[:block.BlockSize()]
		if len(c.IV) != 0 {
			iv = c.IV
		}

		cipherTxt = cipherTxt[block.BlockSize():]
		dst = make([]byte, len(cipherTxt))
		blockMode := cipher.NewCBCDecrypter(block, iv)
		blockMode.CryptBlocks(dst, cipherTxt)

	case BlockModeCFB:
		iv := cipherTxt[:block.BlockSize()]
		if len(c.IV) != 0 {
			iv = c.IV
		}

		cipherTxt = cipherTxt[block.BlockSize():]
		dst = make([]byte, len(cipherTxt))
		cfb := cipher.NewCFBDecrypter(block, iv)
		cfb.XORKeyStream(dst, cipherTxt)

	case BlockModeCTR:
		iv := cipherTxt[:block.BlockSize()]
		if len(c.IV) != 0 {
			iv = c.IV
		}

		cipherTxt = cipherTxt[block.BlockSize():]
		dst = make([]byte, len(cipherTxt))
		ctr := cipher.NewCTR(block, iv)
		ctr.XORKeyStream(dst, cipherTxt)

	case BlockModeGCM:
		if len(c.Nonce) == 0 {
			return nil, ErrNonceIsEmpty
		}

		var aesgcm cipher.AEAD
		if c.TagSize != 0 {
			aesgcm, err = cipher.NewGCMWithTagSize(block, c.TagSize)
		} else {
			aesgcm, err = cipher.NewGCMWithNonceSize(block, len(c.Nonce))
		}

		if err != nil {
			return nil, err
		}

		return aesgcm.Open(nil, c.Nonce, cipherTxt, c.AdditionalData)

	case BlockModeOFB:
		iv := cipherTxt[:block.BlockSize()]
		if len(c.IV) != 0 {
			iv = c.IV
		}

		cipherTxt = cipherTxt[block.BlockSize():]
		dst = make([]byte, len(cipherTxt))

		ofb := cipher.NewOFB(block, iv)
		ofb.XORKeyStream(dst, cipherTxt)
		return dst, nil

	default:
		return nil, ErrBlockMode
	}

	switch c.PaddingMode {
	case PaddingModeNone:
	case PaddingModePKCS7:
		dst, err = PKCS7Padding{}.UnPadding(dst, block.BlockSize())
		if err != nil {
			return nil, err
		}
	case PaddingModeZero:
		dst, err = ZerosPadding{}.UnPadding(dst)
		if err != nil {
			return nil, err
		}
	}

	return dst, nil
}

//func AESCBCEncrypt(plainTxt, key []byte, padding PaddingMode) ([]byte, error) {
//	block, err := aes.NewCipher(key)
//	if err != nil {
//		return nil, err
//	}
//
//	if padding != nil {
//		plainTxt = padding.Padding(plainTxt, block.BlockSize())
//	}
//
//	// The IV needs to be unique, but not secure. Therefore it's common to
//	// include it at the beginning of the ciphertext.
//	dst := make([]byte, block.BlockSize()+len(plainTxt))
//	iv := dst[:block.BlockSize()]
//	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
//		return nil, err
//	}
//
//	blockMode := cipher.NewCBCEncrypter(block, iv)
//	blockMode.CryptBlocks(dst[block.BlockSize():], plainTxt)
//
//	return dst, nil
//}
//
//func AESCBCDecrypt(cipherTxt, key []byte, padding Padding) ([]byte, error) {
//	block, err := aes.NewCipher(key)
//	if err != nil {
//		return nil, err
//	}
//
//	if len(cipherTxt) < block.BlockSize() {
//		return nil, errors.New("ciphertext too short")
//	}
//
//	if len(cipherTxt)%block.BlockSize() != 0 {
//		return nil, errors.New("gocrypto/cipher: input not full blocks")
//	}
//
//	iv := cipherTxt[:block.BlockSize()]
//	cipherTxt = cipherTxt[block.BlockSize():]
//
//	blockMode := cipher.NewCBCDecrypter(block, iv)
//
//	dst := make([]byte, len(cipherTxt))
//	blockMode.CryptBlocks(dst, cipherTxt)
//
//	if padding != nil {
//		dst = padding.UnPadding(dst)
//	}
//
//	return dst, nil
//}
//
//func AESECBEncrypt(plainTxt, key []byte, padding Padding) ([]byte, error) {
//	block, err := aes.NewCipher(key)
//	if err != nil {
//		return nil, err
//	}
//
//	if padding != nil {
//		plainTxt = padding.Padding(plainTxt, block.BlockSize())
//	}
//
//	dst := make([]byte, len(plainTxt))
//	blockMode := ecb.NewECBEncrypter(block)
//	blockMode.CryptBlocks(dst, plainTxt)
//
//	return dst, nil
//}
//
//func AESECBDecrypt(cipherTxt, key []byte, padding Padding) ([]byte, error) {
//	block, err := aes.NewCipher(key)
//	if err != nil {
//		return nil, err
//	}
//
//	if len(cipherTxt)%block.BlockSize() != 0 {
//		return nil, errors.New("gocrypto/cipher: input not full blocks")
//	}
//
//	dst := make([]byte, len(cipherTxt))
//	blockMode := ecb.NewECBDecrypter(block)
//	blockMode.CryptBlocks(dst, cipherTxt)
//
//	if padding != nil {
//		dst = padding.UnPadding(dst)
//	}
//
//	return dst, nil
//}
//
//func AESCFBEncrypt(plainTxt, key []byte, padding Padding) ([]byte, error) {
//	block, err := aes.NewCipher(key)
//	if err != nil {
//		return nil, err
//	}
//
//	if padding != nil {
//		plainTxt = padding.Padding(plainTxt, block.BlockSize())
//	}
//
//	// The IV needs to be unique, but not secure. Therefore it's common to
//	// include it at the beginning of the ciphertext.
//	dst := make([]byte, block.BlockSize()+len(plainTxt))
//	iv := dst[:block.BlockSize()]
//	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
//		return nil, err
//	}
//
//	cfb := cipher.NewCFBEncrypter(block, iv)
//	cfb.XORKeyStream(dst, plainTxt)
//
//	return dst, nil
//}
//
//func AESCFBDecrypt(cipherTxt, key []byte, padding Padding) ([]byte, error) {
//	block, err := aes.NewCipher(key)
//	if err != nil {
//		return nil, err
//	}
//
//	if len(cipherTxt) < block.BlockSize() {
//		return nil, errors.New("ciphertext too short")
//	}
//
//	if len(cipherTxt)%block.BlockSize() != 0 {
//		return nil, errors.New("gocrypto/cipher: input not full blocks")
//	}
//
//	iv := cipherTxt[:block.BlockSize()]
//	cipherTxt = cipherTxt[block.BlockSize():]
//
//	cfb := cipher.NewCFBDecrypter(block, iv)
//
//	dst := make([]byte, len(cipherTxt))
//	cfb.XORKeyStream(dst, cipherTxt)
//
//	if padding != nil {
//		dst = padding.UnPadding(dst)
//	}
//
//	return dst, nil
//}
//
//func AESCTREncrypt(plainTxt, key []byte, padding Padding) ([]byte, error) {
//	block, err := aes.NewCipher(key)
//	if err != nil {
//		return nil, err
//	}
//
//	if padding != nil {
//		plainTxt = padding.Padding(plainTxt, block.BlockSize())
//	}
//
//	// The IV needs to be unique, but not secure. Therefore it's common to
//	// include it at the beginning of the ciphertext.
//	dst := make([]byte, block.BlockSize()+len(plainTxt))
//	iv := dst[:block.BlockSize()]
//	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
//		return nil, err
//	}
//
//	ctr := cipher.NewCTR(block, iv)
//	ctr.XORKeyStream(dst, plainTxt)
//
//	return dst, nil
//}
//
//func AESCTRDecrypt(cipherTxt, key []byte, padding Padding) ([]byte, error) {
//	block, err := aes.NewCipher(key)
//	if err != nil {
//		return nil, err
//	}
//
//	if len(cipherTxt) < block.BlockSize() {
//		return nil, errors.New("ciphertext too short")
//	}
//
//	if len(cipherTxt)%block.BlockSize() != 0 {
//		return nil, errors.New("gocrypto/cipher: input not full blocks")
//	}
//
//	iv := cipherTxt[:block.BlockSize()]
//	cipherTxt = cipherTxt[block.BlockSize():]
//
//	ctr := cipher.NewCTR(block, iv)
//
//	dst := make([]byte, len(cipherTxt))
//	ctr.XORKeyStream(dst, cipherTxt)
//
//	if padding != nil {
//		dst = padding.UnPadding(dst)
//	}
//
//	return dst, nil
//}
//
//func AESGCMEncrypt(plainTxt, key []byte, padding Padding) ([]byte, error) {
//	block, err := aes.NewCipher(key)
//	if err != nil {
//		return nil, err
//	}
//
//	if padding != nil {
//		plainTxt = padding.Padding(plainTxt, block.BlockSize())
//	}
//
//	dst := make([]byte, len(plainTxt))
//	aesgcm, err := cipher.NewGCM(block)
//	if err != nil {
//		return nil, err
//	}
//
//	nonce := make([]byte, 12)
//	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
//		panic(err.Error())
//	}
//
//	dst = aesgcm.Seal(nil, nonce, plainTxt, nil)
//
//	return dst, nil
//}
//
//func AESGCMDecrypt(cipherTxt, key, nonce []byte) ([]byte, error) {
//	block, err := aes.NewCipher(key)
//	if err != nil {
//		return nil, err
//	}
//
//	if len(nonce) != 12 {
//		return nil, errors.New("incorrect nonce length given to GCM")
//	}
//
//	aesgcm, err := cipher.NewGCM(block)
//	if err != nil {
//		return nil, err
//	}
//
//	plaintext, err := aesgcm.Open(nil, nonce, cipherTxt, nil)
//	if err != nil {
//		return nil, err
//	}
//
//	return plaintext, nil
//}
//
//func AESOFBEncrypt(plainTxt, key []byte, padding Padding) ([]byte, error) {
//	block, err := aes.NewCipher(key)
//	if err != nil {
//		return nil, err
//	}
//
//	if padding != nil {
//		plainTxt = padding.Padding(plainTxt, block.BlockSize())
//	}
//
//	// The IV needs to be unique, but not secure. Therefore it's common to
//	// include it at the beginning of the ciphertext.
//	ciphertext := make([]byte, block.BlockSize()+len(plainTxt))
//	iv := ciphertext[:block.BlockSize()]
//	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
//		panic(err)
//	}
//
//	ofb := cipher.NewOFB(block, iv)
//	ofb.XORKeyStream(ciphertext[block.BlockSize():], plainTxt)
//
//	return ciphertext, nil
//}
//
//func AESOFBDecrypt(cipherTxt, key []byte) ([]byte, error) {
//	block, err := aes.NewCipher(key)
//	if err != nil {
//		return nil, err
//	}
//
//	if len(cipherTxt) < block.BlockSize() {
//		return nil, errors.New("ciphertext too short")
//	}
//
//	if len(cipherTxt)%block.BlockSize() != 0 {
//		return nil, errors.New("gocrypto/cipher: input not full blocks")
//	}
//
//	iv := cipherTxt[:block.BlockSize()]
//	cipherTxt = cipherTxt[block.BlockSize():]
//
//	ofb := cipher.NewOFB(block, iv)
//
//	dst := make([]byte, len(cipherTxt))
//	ofb.XORKeyStream(dst, cipherTxt)
//
//	return dst, nil
//}
