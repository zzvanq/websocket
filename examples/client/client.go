package main

import (
	"context"
	"fmt"
	"github.com/zzvanq/websocket"
)

func main() {
	conn, err := websocket.Dial(context.Background(), "ws://localhost:8080")
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	text := ""
	for {
		fmt.Scan(&text)
		if text == "exit" {
			break
		}

		err := conn.Write(websocket.TextFrame, []byte(text))
		if err != nil {
			panic(err)
		}

		msg, err := conn.Read()
		if err != nil {
			panic(err)
		}
		fmt.Println(string(msg.Data))
	}
}
