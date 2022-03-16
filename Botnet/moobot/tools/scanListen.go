package main
import (
    "bufio"
    "fmt"
    "strings"
    "net"
    "time"
)
func main() {
    l, err := net.Listen("tcp", "198.98.49.193:774")
    if err != nil {
        fmt.Println(err)
        return
    }
    for {
        conn, err := l.Accept()
        if err != nil {
            break
        }
        go handleConnection(conn)
    }
}
func handleConnection(conn net.Conn) {
    defer conn.Close()
    conn.SetDeadline(time.Now().Add(10 * time.Second))
    message, _ := bufio.NewReader(conn).ReadString('\n')
    if strings.Contains(string(message), "[telnet]") || strings.Contains(string(message), "[hisilicon]") {
    	fmt.Printf("%s\n", string(message))
    }
}
