package main

import (
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// Submission represents a single item posted to /submit.
// Keep the fields generic so participants can post test flags or messages.
type Submission struct {
	ID        int       `json:"id"`
	Source    string    `json:"source"`    // e.g. url where the payload ran
	Data      string    `json:"data"`      // user-provided test string (flags, tokens for lab)
	Note      string    `json:"note"`      // optional note
	IP        string    `json:"ip"`        // observed remote addr
	CreatedAt time.Time `json:"created_at"`
}

var (
	mu          sync.Mutex
	submissions []Submission
	nextID      = 1
	dataFile    = "submissions.json"
	tmpl        = template.Must(template.New("dash").Parse(dashboardHTML))
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

	http.HandleFunc("/", dashboardHandler)
	http.HandleFunc("/submit", submitHandler)
	http.HandleFunc("/submissions", submissionsAPIHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	addr := ":" + port
	log.Printf("starting CTF-safe XSS backend on %s (datafile=%s)", addr, dataFile)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("server failed: %v", err)
	}
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

// submitHandler accepts POST requests with application/json or form data.
// For CTF safety we explicitly encourage posting non-sensitive test flags only.
func submitHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var s Submission

	ct := r.Header.Get("Content-Type")
	if ct == "application/json" || r.Header.Get("Accept") == "application/json" {
		dec := json.NewDecoder(r.Body)
		var tmp map[string]interface{}
		if err := dec.Decode(&tmp); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		if v, ok := tmp["source"].(string); ok {
			s.Source = v
		}
		if v, ok := tmp["data"].(string); ok {
			s.Data = v
		}
		if v, ok := tmp["note"].(string); ok {
			s.Note = v
		}
	} else {
		// form data fallback
		r.ParseForm()
		s.Source = r.FormValue("source")
		s.Data = r.FormValue("data")
		s.Note = r.FormValue("note")
	}

	// Limit length to avoid resource abuse in a shared environment.
	if len(s.Data) > 5000 {
		http.Error(w, "data too long", http.StatusBadRequest)
		return
	}

	s.IP = remoteIP(r)
	s.CreatedAt = time.Now()

	mu.Lock()
	s.ID = nextID
	nextID++
	submissions = append([]Submission{s}, submissions...)
	// keep only recent 1000 in memory
	if len(submissions) > 1000 {
		submissions = submissions[:1000]
	}
	mu.Unlock()

	// persist asynchronously but do a best-effort save
	if err := saveSubmissions(); err != nil {
		log.Printf("warning: could not save submissions: %v", err)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"status": "ok", "id": s.ID})
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

func remoteIP(r *http.Request) string {
	// Try X-Forwarded-For then fallback to RemoteAddr
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		// may contain comma-separated list; take the first
		for i := 0; i < len(xff); i++ {
			if xff[i] == ',' {
				return xff[:i]
			}
		}
		return xff
	}
	ra := r.RemoteAddr
	// RemoteAddr is usually host:port. Strip port if present.
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
	// set nextID
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
	// write to temp file then rename to avoid corruption
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

const dashboardHTML = `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>CTF XSS Backend (Safe)</title>
<style>
body{font-family:system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:20px}
table{border-collapse:collapse;width:100%}
th,td{padding:8px;border:1px solid #ddd;text-align:left}
.small{font-size:0.9em;color:#666}
</style>
</head>
<body>
<h1>CTF XSS Backend (Safe)</h1>
<p class="small">This server is intended for CTF / lab use only. Do not use it to collect real users' cookies or other sensitive information.</p>
<p class="small">POST to <code>/submit</code> with fields: <code>source</code>, <code>data</code>, <code>note</code>. Use JSON or form-encoded requests.</p>
<h2>Recent submissions</h2>
<table>
<thead>
<tr><th>ID</th><th>When</th><th>Source</th><th>Data</th><th>Note</th><th>IP</th></tr>
</thead>
<tbody>
{{range .Submissions}}
<tr>
<td>{{.ID}}</td>
<td>{{.CreatedAt.Format "2006-01-02 15:04:05"}}</td>
<td>{{.Source}}</td>
<td><pre style="white-space:pre-wrap;margin:0">{{.Data}}</pre></td>
<td>{{.Note}}</td>
<td>{{.IP}}</td>
</tr>
{{else}}
<tr><td colspan="6">No submissions yet</td></tr>
{{end}}
</tbody>
</table>
</body>
</html>`
