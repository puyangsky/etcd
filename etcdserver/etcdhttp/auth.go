package etcdhttp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
)

// etdited by puyangsky
const (
	LOGFILEPATH  = "/home/pyt/k8slog/log.log"
	LOGFILEPATH1 = "/home/pyt/k8slog/loadPolicy.log"
	POLICYPATH   = "/home/pyt/k8slog/policy.txt"
	NEWPOLICY    = "/home/pyt/k8slog/newPolicy.txt"
	ERRLOG       = "/home/pyt/k8slog/err.log"
)

func loadPolicy() []string {
	logger1.Println("Invoking loadPolicy...")
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
	return policies
}

var (
	logFile, _  = os.OpenFile(LOGFILEPATH, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
	logger      = log.New(logFile, "", log.LstdFlags|log.Llongfile)
	logFile1, _ = os.OpenFile(LOGFILEPATH1, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
	logger1     = log.New(logFile1, "", log.LstdFlags|log.Llongfile)
	errLog, _   = os.OpenFile(ERRLOG, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
	errLogger   = log.New(errLog, "", log.LstdFlags|log.Llongfile)
	// POLICY is a global variable
	POLICY = loadPolicy()
)

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

func authorize(w http.ResponseWriter, r *http.Request, switcher bool) {
	url := r.URL.Path[len(keysPrefix):]
	method := r.Method
	subject := r.Header.Get("Subject")

	p := &request{url, method, subject}

	// for logging use
	pJSON, err := json.Marshal(p)
	checkErr(err)
	content := fmt.Sprintf("%s\n", pJSON)
	logger.Printf("%s", content)

	// do real check to subject of request
	if switcher {
		if !coreAuthorize(p) {
			// log the forbidden request
			errLogger.Println("403Forbidden\t", content)
			// writeError(w, r, httptypes.NewHTTPError(http.StatusForbidden, "Not authorized"))
			// return
		}
	} else {
		generatePolicy(p)
	}
}

func coreAuthorize(r *request) bool {
	policy := POLICY
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
		if parseURL(r.URL) == items[0] && strings.ToLower(r.Method) == strings.ToLower(items[1]) && isAllowedSubject {
			return true
		}
	}
	return false
}

func generatePolicy(p *request) {
	if p.Subject != "" && len(p.Subject) > 0 {
		subject := strings.Replace(p.Subject, "##", "\n", -1)
		content := fmt.Sprintf("%s, %s\n%s\n\n", p.URL, p.Method, subject)
		f, err := os.OpenFile(NEWPOLICY, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
		checkErr(err)
		_, err = io.WriteString(f, content)
		checkErr(err)
		defer f.Close()
	}
}

func parseURL(url string) string {
	uuidPattern, _ := regexp.Compile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
	url = uuidPattern.ReplaceAllString(url, "%UUID%")

	numPattern, _ := regexp.Compile("/([^/]*([0-9]|test|my|auth-|pv)[^/]*|a$|pi$|rc$|quotaed.*|patch.*|allocatable.*|client.*|selflink.*|xxx$|[^/]*-[^/]*)")
	url = numPattern.ReplaceAllString(url, "/%NAME%")

	numPattern2, _ := regexp.Compile("/(%NAME%.*|secret/%NAME%)")
	url = numPattern2.ReplaceAllString(url, "/%NAME%")
	return url
}
