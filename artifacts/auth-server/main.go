package main

import (
	"fmt"
	"log"
	"net/http"
)

func main()  {
	http.HandleFunc("/v1/login", func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("invalid authentication mechanism"))
			return
		}

		fmt.Println(username, password)
		if username == "admin" && password == "admin" {
			w.WriteHeader(http.StatusOK)
			return
		} else if username == "nahid" && password == "nahid" {
			w.WriteHeader(http.StatusOK)
			return
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("invalid user/pass"))
			return
		}
	})
	if err := http.ListenAndServe("0.0.0.0:5001", http.DefaultServeMux); err != nil {
		log.Fatal(err)
	}
}