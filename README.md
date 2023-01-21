# GolangRAT
## Golang remote administration toolkit
This is tool to control your computer using telegram bot.
## Build
- Windows
To build this application on windows you should use `build.bat`.
But before you build, you should change `ADMIN_ID` in `vars.go` to your telegram id(to recieve pushes when the rat starts) and `BOT_TOKEN` to token of your telegram bot.


### To do:

- [ ] Replace some of the functions with C code
- [x] Add a keylogger
- [ ] Add linux support

V1.0
Keylogger added. Need to implement a stop function for the keylogger.

Notes: Infinite loop in the keylogger.