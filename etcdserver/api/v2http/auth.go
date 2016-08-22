package v2http

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// etdited by puyangsky

// definition of our wrapped request
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

	// for logging use
	filename := "/home/pyt/k8slog/header.log"
	tm := time.Now().Format("2006-01-02 15:04:05")
	content := fmt.Sprintf("[%s]\tsubject: %s, method: %s, url: %s, json: %s\n", tm, subject, method, url, pJSON)
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
	checkErr(err)
	_, err = io.WriteString(f, content)
	checkErr(err)
	f.Close()

	return ok && coreAuthorize(p)
}

func loadPolicy() []string {
	filename := "/home/pyt/k8slog/policy.txt"
	f, _ := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
	defer f.Close()
	buf := make([]byte, 1024)
	// use byteBuffer to accelerate appending all strings instead of +=
	var sb bytes.Buffer
	for {
		n, _ := f.Read(buf)
		if 0 == n {
			break
		}
		s := string(buf[:n])
		sb.WriteString(s)
	}
	policy := sb.String()
	var policies []string
	policies = strings.Split(policy, "\n\n")
	// for item := range policies {
	// 	fmt.Println(item, ">>>>>>", policies[item])
	// }
	return policies
}

func coreAuthorize(r *request) bool {
	policy := loadPolicy()
	for i := range policy {
		lines := strings.Split(policy, "\n")
		if len(lines) < 1 {
			continue
		}
		isAllowedSubject := false
		for j := 1; j < len(lines); j++ {
			// as defualt there is only one subject per request
			if lines[j] == r.Subject[0] {
				isAllowedSubject = true
			}
		}
		items := strings.Split(lines[0], ", ")
		if r.URL == items[0] && r.Method == items[1] && isAllowedSubject {
			return true
		}
	}
	return false
}
