package main

import (
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"os"
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

func remoteIP(r *http.Request) string {
	// Try X-Forwarded-For then fallback to RemoteAddr
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		// may contain comma-separated list; take the first
		for i := 0; i < len(xff); i++ {
			if xff[i] == ',' {
				return strings.TrimSpace(xff[:i])
			}
		}
		return strings.TrimSpace(xff)
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
