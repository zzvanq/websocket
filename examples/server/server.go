package main

import (
	"fmt"
	"github.com/zzvanq/websocket"
	"net/http"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Upgrade(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		defer conn.Close()
		for {
			msg, err := conn.Read()
			if err != nil {
				fmt.Println("read error:", err)
				return
			}
			fmt.Println("read:", string(msg.Data))
			err = conn.Write(msg.Type, msg.Data)
			if err != nil {
				fmt.Println("write error:", err)
				return
			}
		}
	})

	http.ListenAndServe(":8080", mux)
}
