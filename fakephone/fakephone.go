package fakephone

import (
	"bytes"
	cryptorand "crypto/rand"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"time"

	uuid "github.com/satori/go.uuid"
)

func RandMac() string {
	buf := make([]byte, 6)

	_, err := cryptorand.Read(buf)
	if err != nil {
		return ""

	}

	// Set the local bit
	buf[0] |= 2

	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		buf[0], buf[1], buf[2], buf[3], buf[4], buf[5])

}

// get from github.com/FROSTEROID/go_IMEI_checker_generator
func GenIMEI() string {
	const IMEI_BASE_DIGITS_COUNT int = 14 // The number of digits without the last - the control one.
	const ASCII_ZERO_NUMBER uint8 = 48

	var sum int = 0 // the control sum of digits
	var toAdd int = 0
	var digits [IMEI_BASE_DIGITS_COUNT + 1]int // darray for dadigits

	lolrndsrc := rand.NewSource(time.Now().UnixNano()) // creating a randomizer instance initiated with TIME!
	lolrnd := rand.New(lolrndsrc)

	imei := ""

	for i := 0; i < IMEI_BASE_DIGITS_COUNT; i++ { // generating all the base digits
		digits[i] = lolrnd.Intn(10) // with lolrnd.Intn
		toAdd = digits[i]
		if (i+1)%2 == 0 { // special proc for every 2nd one
			toAdd *= 2
			if toAdd >= 10 {
				toAdd = (toAdd % 10) + 1
			}
		}
		sum += toAdd // and summarizing
		//fmt.Printf("%d", digits[i]) // and even printing them here!
		imei += strconv.Itoa(digits[i])
	}
	var ctrlDigit int = (sum * 9) % 10         // calculating the control digit
	digits[IMEI_BASE_DIGITS_COUNT] = ctrlDigit // adding to darray
	//fmt.Printf("%d", ctrlDigit)
	imei += strconv.Itoa(ctrlDigit)

	// fmt.Println(imei)

	return imei
}

func GenIMSI() string {
	// MCC（Mobile Country Code，移动国家码）：MCC的资源由国际电信联盟（ITU）在全世界范围内统一分配和管理，
	// 唯一识别移动用户所属的国家，共3位，中国为460
	imsi := "460"
	// MNC（Mobile Network Code，移动网络号码）：用于识别移动用户所归属的移动通信网，2~3位
	// 中国移动系统使用00、02、04、07，中国联通GSM系统使用01、06、09，中国电信CDMA系统使用03、05、电信4G使用11，中国铁通系统使用20
	mncArray := []string{"00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "11", "20"}

	imsi += mncArray[rand.Intn(len(mncArray))]
	for i := 0; i < 10; i++ {
		imsi += strconv.Itoa(rand.Intn(10))
	}

	return imsi
}

const hextable = "0123456789abcdef"

// 生成AndroidID
func AndroidID() string {
	rand.Seed(time.Now().UnixNano())

	var buff bytes.Buffer
	for i := 0; i < 16; i++ {
		index := rand.Intn(16)
		buff.WriteByte(hextable[index])
	}

	return buff.String()
}

func SerialNumber() string {
	rand.Seed(time.Now().UnixNano())

	var buff bytes.Buffer
	for i := 0; i < 13; i++ {
		index := rand.Intn(16)
		buff.WriteByte(hextable[index])
	}

	return strings.ToUpper(buff.String())
}

// UUID 56bd51e2-fe5e-42cf-adf2-036c5e341d6c
func UUID() string {
	return uuid.NewV4().String()
}

// 生成DeviceID
func DeviceID() string {
	uuid := make([]byte, 16)
	n, err := rand.Read(uuid)
	if n != len(uuid) || err != nil {
		return ""
	}

	return hex.EncodeToString(uuid)
}
