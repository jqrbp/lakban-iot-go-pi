package main

import (
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"

	// "net"
	// "net/url"
	"net/http"
	// "net/http/httputil"

	// "io"
	"io/ioutil"
	"time"

	"encoding/base64"
	"os"
	"regexp"
	// "encoding/hex"

	"crypto/aes"
	"crypto/cipher"
	"math/rand"
)

func getUrl(_url string) (string, error) {
	timeout := time.Duration(1 * time.Second)
	client := http.Client{
		Timeout: timeout,
	}

	resp, err := client.Get(_url)

	if err != nil {
		return "", err
	}

	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)

	if body != nil {
		return string(body), nil
	}

	return "", nil
}

func checkIP(_id string, _ipSearchStr string, _ipTgtPort string, _lastSearch bool) (string, bool, error) {
	var re = regexp.MustCompile(`[^a-z0-9-$?%&*#@!<>]`)
	// log.Println("Checking: " + _ipSearchStr)
	conRunCnt = conRunCnt + 1
	timeout := time.Duration(1 * time.Second)
	client := http.Client{
		Timeout: timeout,
	}

	resp, err := client.Get("http://" + _ipSearchStr + ":" + _ipTgtPort + "/id")

	if err != nil {
		if _lastSearch == true {
			if wmsFoundFlag == false {
				lastSearchFlag = true
			}
		}
		conRunCnt = conRunCnt - 1
		return "", false, err
	}

	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)

	if body != nil {
		bodystr := re.ReplaceAllString(string(body), "")
		if bodystr == _id {
			wmsIP = _ipSearchStr
			wmsFoundFlag = true
		}
	}

	if _lastSearch == true {
		if wmsFoundFlag == false {
			lastSearchFlag = true
		}
	}

	conRunCnt = conRunCnt - 1
	return "", false, nil
}

func getWmsKey(_ip string, _port string) string {
	if wmsFoundFlag == true {
		aesKeyFlag = false
		aesEncKeyStr, err := getUrl("http://" + _ip + ":" + _port + "/kes")
		if err != nil {
			log.Println(err)
			return ""
		}
		// log.Println("getKey: " + aesEncKeyStr)

		aesEncKey, errDec := base64.StdEncoding.DecodeString(aesEncKeyStr)
		if errDec != nil {
			log.Println("decode error:", errDec)
			return ""
		}

		aesMasterIv := aesEncKey[len(aesEncKey)-16:]
		aesEnc := aesEncKey[:len(aesEncKey)-16]

		// log.Println("aesEncKey:", hex.EncodeToString(aesEncKey))
		// log.Println("iv:", hex.EncodeToString(aesIv))
		// log.Println("aesEnc:", hex.EncodeToString(aesEnc))

		block, err := aes.NewCipher(aesMasterKey)
		if err != nil {
			panic(err)
		}

		if len(aesEnc) < aes.BlockSize {
			panic("ciphertext too short")
		}

		if len(aesEnc)%aes.BlockSize != 0 {
			panic("ciphertext is not a multiple of the block size")
		}

		mode := cipher.NewCBCDecrypter(block, aesMasterIv)
		mode.CryptBlocks(aesEnc, aesEnc)

		aesKey = aesEnc[:32]
		aesIv = aesEnc[len(aesEnc)-16:]
		// log.Println("aesKey:", hex.EncodeToString(aesKey))
		aesKeyFlag = true
	}
	return ""
}

func findWemosServer(_id string, _ipSearchStr string, _port string) string {
	wmsFoundFlag = false
	wmsIP = ""
	str := ""
	for i := ipSearchNumStart; i <= ipSearchNumEnd; i++ {
		str = _ipSearchStr + "." + strconv.Itoa(i)
		// log.Println("finding: " + str)
		go checkIP(_id, str, _port, false)
	}

	go checkIP(_id, str, _port, true)

	for conRunCnt > 0 {
		if wmsFoundFlag == true {
			break
		}
		if lastSearchFlag == true {
			break
		}
	}

	// if wmsIP != "" {
	// 	log.Println("found: " + wmsIP)
	// }

	return ""
}

func setNumCmd(_cmd string) {
	tmp := 0
	numCmd = 0
	// OFF ~ HIGH
	// ON ~ LOW
	for i := 0; i < len(_cmd); i++ {
		tmp = int(_cmd[i] - 48)
		if tmp > 0 {
			numCmd = numCmd * 2
		} else {
			numCmd = numCmd*2 + 1
		}
	}
}

func respVerify(_numCmd int, _state int, _tgl string) string {
	strTmp := ""

	if strings.Compare(_tgl, "or") == 0 {
		strTmp = fmt.Sprintf("ledRes%d", (_state | _numCmd))
	} else if strings.Compare(_tgl, "and") == 0 {
		strTmp = fmt.Sprintf("ledRes%d", (_state & _numCmd))
	} else if strings.Compare(_tgl, "xor") == 0 {
		strTmp = fmt.Sprintf("ledRes%d", (_state ^ _numCmd))
	} else {
		strTmp = fmt.Sprintf("ledRes%d", numCmd)
	}

	return strTmp
}

func randomByte(l int) []byte {
	bytes := make([]byte, l)
	for i := 0; i < l; i++ {
		bytes[i] = byte(randInt(0, 255))
	}
	return bytes
}

func randInt(min int, max int) int {
	return min + rand.Intn(max-min)
}

func genMorsStr(_num int, _len int) string {
	strOut := ""
	randBytes := randomByte(_len)

	for i := 0; i < _len; i++ {
		if i == 4 {
			strOut += fmt.Sprintf("%02X", _num)
		} else {
			strOut += fmt.Sprintf("%02X", randBytes[i])
		}
	}

	return strOut
}

func sendWmsCmd(_ip string, _port string, _tglcmd string, _num int, _key []byte, _iv []byte) string {
	cmdOut := genMorsStr(_num, len(_iv))
	stateStr := ""

	if aesKeyFlag == true {
		if len(aesStateTemp)%aes.BlockSize != 0 {
			panic("aesStateTemp is not a multiple of the block size")
		}

		block, err := aes.NewCipher(_key)
		if err != nil {
			panic(err)
		}

		// The IV needs to be unique, but not secure. Therefore it's common to
		// include it at the beginning of the ciphertext.
		ciphertext := make([]byte, len(aesStateTemp))

		mode := cipher.NewCBCEncrypter(block, _iv)
		mode.CryptBlocks(ciphertext, aesStateTemp)

		// It's important to remember that ciphertexts must be authenticated
		// (i.e. by using crypto/hmac) as well as being encrypted in order to
		// be secure.
		// stateStrB64 := base64.StdEncoding.EncodeToString(ciphertext)
		stateStrB64 := base64.StdEncoding.EncodeToString(ciphertext)
		// fmt.Printf("stateStr = %s\n", stateStr)
		// fmt.Printf("aesStateTemp = %s\n", base64.StdEncoding.EncodeToString(aesStateTemp))

		for i := 0; i < len(stateStrB64); i++ {
			stateStr += fmt.Sprintf("%02X", stateStrB64[i])
		}

		// log.Println("state: " + stateStrB64)
		// log.Println("state: " + stateStr)

		urlString := "http://" + wmsIP + ":" + _port + "/lnk?stat=" + stateStr + "&mors=" + cmdOut + "&tgl=" + _tglcmd
		// log.Println("mors: " + cmdOut)
		// log.Println("tgl: " + _tglcmd)
		resp, err := getUrl(urlString)

		if err != nil {
			log.Println(err)
			return ""
		}

		// log.Println("cmd resp: " + resp)
		return resp
	}

	return ""
}

func getWmsCmd(_ip string, _port string, _tglcmd string, _num int, _key []byte, _iv []byte) (int, error) {
	cmdOut := genMorsStr(_num, len(_iv))
	stateStr := ""

	if aesKeyFlag == true {
		if len(aesStateTemp)%aes.BlockSize != 0 {
			panic("aesStateTemp is not a multiple of the block size")
		}

		block, err := aes.NewCipher(_key)
		if err != nil {
			panic(err)
		}

		// The IV needs to be unique, but not secure. Therefore it's common to
		// include it at the beginning of the ciphertext.
		ciphertext := make([]byte, len(aesStateTemp))

		mode := cipher.NewCBCEncrypter(block, _iv)
		mode.CryptBlocks(ciphertext, aesStateTemp)

		// It's important to remember that ciphertexts must be authenticated
		// (i.e. by using crypto/hmac) as well as being encrypted in order to
		// be secure.
		// stateStrB64 := base64.StdEncoding.EncodeToString(ciphertext)
		stateStrB64 := base64.StdEncoding.EncodeToString(ciphertext)

		for i := 0; i < len(stateStrB64); i++ {
			stateStr += fmt.Sprintf("%02X", stateStrB64[i])
		}

		urlString := "http://" + wmsIP + ":" + _port + "/ste?stat=" + stateStr + "&mors=" + cmdOut + "&tgl=" + _tglcmd
		resp, err := getUrl(urlString)

		if err != nil {
			return -1, err
		}

		if strings.Compare(resp, "ok") == 0 {
			return -1, errors.New("Response OK")
		}

		respi, errc := strconv.Atoi(resp)

		if errc != nil {
			return -1, errc
		}

		return respi, nil
	}

	return -1, errors.New("No Response")
}

func main() {
	var srvErr error
	srvRespInt := -1
	srvResp := ""
	arg := os.Args
	tglarg := "no"
	tryCnt := 0
	onval := 1
	offval := 0

	rand.Seed(time.Now().UTC().UnixNano())

	if len(arg) > 5 {
		findWemosServer(arg[2], arg[3], arg[4])
		setNumCmd(arg[5])

		if len(arg) > 6 {
			tglarg = arg[6]
		}

		if len(arg) > 7 {
			if strings.Compare(arg[7], "flip") == 0 {
				onval = 0
				offval = 1
			}
		}

		tryCnt = 0
		for (srvRespInt < 0 || srvErr != nil) && !lastSearchFlag {
			getWmsKey(wmsIP, arg[4])
			srvRespInt, srvErr = getWmsCmd(arg[2], arg[4], tglarg, numCmd, aesKey, aesIv)
			// log.Println("get resp: ", srvRespInt)
			tryCnt = tryCnt + 1
			if tryCnt > 50 {
				fmt.Fprintf(os.Stderr, "get max try %d, error: %s, resp: %d\n\r", tryCnt, srvErr, srvRespInt)
				return
			}
		}

		if lastSearchFlag {
			fmt.Fprintln(os.Stderr, "Not Found")
			return
		}

		if strings.Compare(arg[1], "set") == 0 {
			tryCnt = 0
			srvRespV := respVerify(numCmd, srvRespInt, tglarg)

			for (srvResp != srvRespV) && (lastSearchFlag == false) {
				getWmsKey(wmsIP, arg[4])

				srvResp = sendWmsCmd(arg[2], arg[4], tglarg, numCmd, aesKey, aesIv)
				tryCnt = tryCnt + 1
				if tryCnt > 50 {
					fmt.Fprintf(os.Stderr, "set max try %d, error: %s, resp: %s - %s\n\r", tryCnt, srvErr, srvResp, srvRespV)
					return
				}
			}
		}

		if strings.Compare(arg[1], "get") == 0 {
			if srvRespInt < 0 {
				fmt.Fprintln(os.Stderr, "No Response")
			} else if srvRespInt > 0 {
				fmt.Printf("state: %d\n\r", onval)
			} else {
				fmt.Printf("state: %d\n\r", offval)
			}
		}
	} else {
		println("usage wemos-cmd-go <set/get> <id> <iprange> <port> <cmd> <toggle>")
		println("toggle tips: or=>(0: off, 1: ignore), and=>(1: on, 0: ignore)")
	}
}
