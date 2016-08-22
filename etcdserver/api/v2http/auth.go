package v2http

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// etdited by puyangsky
type request struct {
	URL     string   `json:"URL"`
	Method  string   `json:"method"`
	Subject []string `json:"subject"`
}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}

func authorize(r *http.Request) bool {
	header := r.Header
	url := r.URL.Path
	method := r.Method
	subject, ok := header["Subject"]

	p := &request{url, method, subject}

	pJSON, err := json.Marshal(p)
	checkErr(err)

	filename := "/home/pyt/k8slog/header.log"
	tm := time.Now().Format("2006-01-02 15:04:05")
	content := fmt.Sprintf("[%s]\tsubject: %s, method: %s, url: %s, json: %s\n", tm, subject, method, url, pJSON)
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
	checkErr(err)
	_, err = io.WriteString(f, content)
	checkErr(err)
	f.Close()

	return ok
}

func (p *request) Auth() bool {
	return false
}
