package v2http

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
)

// etdited by puyangsky
const (
	LOGFILEPATH = "/home/pyt/k8slog/log.log"
	// LOGFILEPATH1 = "/home/pyt/k8slog/log1.log"
	POLICYPATH = "/home/pyt/k8slog/policy.txt"
)

var (
	logFile, _ = os.OpenFile(LOGFILEPATH, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
	logger     = log.New(logFile, "", log.LstdFlags|log.Llongfile)
	// logFile1, _ = os.OpenFile(LOGFILEPATH1, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
	// logger1     = log.New(logFile1, "", log.LstdFlags|log.Llongfile)
)

// func logHeader(r *http.Request) {
// 	sub := r.Header.Get("Subject")
// 	logger1.Println("URL: ", r.URL, " Subject:", sub)
// }

// definition of our wrapped request
type request struct {
	URL     string `json:"URL"`
	Method  string `json:"method"`
	Subject string `json:"subject"`
}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}

func authorize(r *http.Request) bool {
	url := r.URL.Path[len(keysPrefix):]
	method := r.Method
	subject := r.Header.Get("Subject")
	if len(subject) < 1 {
		return false
	}

	p := &request{url, method, subject}

	pJSON, err := json.Marshal(p)
	checkErr(err)

	// for logging use
	content := fmt.Sprintf("%s\n", pJSON)
	logger.Printf("%s", content)

	return coreAuthorize(p)
}

func loadPolicy() []string {
	filename := POLICYPATH
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
		lines := strings.Split(policy[i], "\n")
		if len(lines) < 1 {
			continue
		}
		isAllowedSubject := false
		subjectItems := strings.Split(r.Subject, "##")
		if len(lines)-1 == len(subjectItems) {
			for j := 1; j < len(lines); j++ {
				if lines[j] == subjectItems[j-1] {
					isAllowedSubject = true
				} else {
					isAllowedSubject = false
					break
				}
			}
		}

		items := strings.Split(lines[0], ", ")
		if r.URL == items[0] && strings.ToLower(r.Method) == strings.ToLower(items[1]) && isAllowedSubject {
			return true
		}
	}
	return false
}
