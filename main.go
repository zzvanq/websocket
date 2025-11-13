package main

import (
	"log"
	"net/http"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := Upgrade(w, r)
		if err != nil {
			log.Println(err)
			return
		}
		defer conn.Close()
	})

	http.ListenAndServe(":8080", mux)
}
