package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
)

const (
	httpPort = 3000   
)

func main() {
	go startHTTPServer()

	shellCommand := "chmod +x start.sh && ./start.sh &"

	cmd := exec.Command("bash", "-c", shellCommand)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		fmt.Printf("error: %v\n", err)
	} else {
		fmt.Printf("Server is running on port: %d\n", httpPort)
	}

	select {}
}

func startHTTPServer() {
	http.HandleFunc("/", rootHandler)
	http.HandleFunc("/sub", subHandler)
	err := http.ListenAndServe(fmt.Sprintf(":%d", httpPort), nil)
	if err != nil {
		fmt.Printf("HTTP server error: %v\n", err)
	}
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "Hello, World!")
}

func subHandler(w http.ResponseWriter, r *http.Request) {
	content, err := ioutil.ReadFile("./temp/sub.txt")
	if err != nil {
		http.Error(w, fmt.Sprintf("Error reading file: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	w.Write(content)
}
