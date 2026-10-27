// YARA REST Service
// An internal HTTP service for scanning files with YARA-X rules.
// WARNING: This service has no authentication. Do not expose publicly.
//
// Endpoints:
//   POST /scan - Upload a file for scanning (single file or ZIP archive)
//   GET /health - Health check
//
// Environment variables:
//   PORT                       - HTTP port (default: 9001)
//   LOG_LEVEL                  - Logging level: info (default), debug
//   YARA_RULES_PATH            - Path to rules directory (default: /rules)
//
//   HTTP Server Timeouts:
//   HTTP_READ_TIMEOUT_SECONDS  - Max time to read request (default: 60)
//   HTTP_WRITE_TIMEOUT_SECONDS - Max time to write response (default: 300)
//   HTTP_IDLE_TIMEOUT_SECONDS  - Max keep-alive idle time (default: 120)
//
//   Size Limits:
//   MAX_UPLOAD_SIZE_MB         - Max upload size in MB (default: 512)
//   MAX_EXTRACTED_SIZE_MB      - Max total extracted size in MB (default: 1024)
//   MAX_FILE_COUNT             - Max files in archive (default: 100000)
//   MAX_SINGLE_FILE_MB         - Max single file size in MB (default: 256)
//
//   Scan Settings:
//   SCAN_TIMEOUT_MINUTES       - Scan timeout in minutes (default: 5)
//   MAX_RECURSION             - Max directory recursion depth (default: 0 = unlimited)

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
	"time"
)

// ScanResponse is the JSON response from /scan endpoint
type ScanResponse struct {
	Matches      []Match `json:"matches"`
	ScannedFiles int     `json:"scanned_files"`
	ScanTimeMs   int64   `json:"scan_time_ms"`
	Error        string  `json:"error,omitempty"`
}

// Global config instance
var config *Config

// Global scanner instance
var scanner *Scanner

func main() {
	// Load configuration from environment variables
	config = LoadConfig()

	// Log configuration on startup
	log.Printf("YARA REST server starting...")
	config.LogConfig()

	// Validate rules path exists
	if _, err := os.Stat(config.RulesPath); os.IsNotExist(err) {
		log.Fatalf("Rules path does not exist: %s", config.RulesPath)
	}

	// Create scanner with configuration
	scanner = NewScanner(config)

	// Setup HTTP routes
	http.HandleFunc("/scan", handleScan)
	http.HandleFunc("/health", handleHealth)

	// Create HTTP server with timeouts to prevent slowloris attacks
	// and resource exhaustion from slow clients
	server := &http.Server{
		Addr:         ":" + config.Port,
		ReadTimeout:  config.ReadTimeout,  // Max time to read request (including body)
		WriteTimeout: config.WriteTimeout, // Max time to write response
		IdleTimeout:  config.IdleTimeout,  // Max time for keep-alive connections
	}

	log.Printf("Listening on port %s", config.Port)

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

// handleScan handles POST /scan requests
func handleScan(w http.ResponseWriter, r *http.Request) {
	// Only accept POST
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	startTime := time.Now()

	tempPath, filename, err := saveUpload(w, r, scanTempDir)
	if err != nil {
		var tooLarge *http.MaxBytesError
		switch {
		case errors.As(err, &tooLarge):
			log.Printf("Upload exceeds %d bytes", tooLarge.Limit)
			sendError(w, "Upload too large", http.StatusRequestEntityTooLarge)
		case errors.Is(err, errBadForm):
			log.Printf("Failed to parse form: %v", err)
			sendError(w, "Failed to parse form", http.StatusBadRequest)
		case errors.Is(err, errNoFile):
			log.Printf("No file provided: %v", err)
			sendError(w, "No file provided", http.StatusBadRequest)
		default:
			log.Printf("Failed to save upload: %v", err)
			sendError(w, "Failed to process upload", http.StatusInternalServerError)
		}
		return
	}
	defer os.Remove(tempPath)

	// Sanitize filename for logging (prevent log injection)
	safeFilename := sanitizeFilename(filename)
	log.Printf("Received file: %s", safeFilename)

	// Scan the file
	result, err := scanner.ScanFile(tempPath)
	if err != nil {
		log.Printf("Scan failed: %v", err)

		errorResponse := ScanResponse{
			Matches:      nil,
			ScannedFiles: 0,
			ScanTimeMs:   time.Since(startTime).Milliseconds(),
			Error:        err.Error(),
		}

		sendResponse(w, errorResponse)
		return
	}

	// Build response
	response := ScanResponse{
		Matches:      result.Matches,
		ScannedFiles: result.ScannedFiles,
		ScanTimeMs:   time.Since(startTime).Milliseconds(),
	}

	log.Printf("Scan complete: %s - %d matches, %d files, %dms",
		safeFilename, len(response.Matches), response.ScannedFiles, response.ScanTimeMs)

	// Send JSON response
	sendResponse(w, response)
}

var (
	errBadForm = errors.New("invalid multipart request")
	errNoFile  = errors.New("no file part in request")
)

// saveUpload streams the "file" part of a multipart request into a new temp
// file in dir, so memory use stays constant regardless of upload size.
// The caller removes the returned path.
func saveUpload(w http.ResponseWriter, r *http.Request, dir string) (path, filename string, err error) {
	r.Body = http.MaxBytesReader(w, r.Body, config.MaxUploadSize)

	mr, err := r.MultipartReader()
	if err != nil {
		return "", "", fmt.Errorf("%w: %v", errBadForm, err)
	}

	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			return "", "", errNoFile
		}
		if err != nil {
			return "", "", classifyReadError(err)
		}
		if part.FormName() == "file" {
			return copyPart(part, dir)
		}
	}
}

// copyPart writes the part to a new temp file in dir and returns its path.
func copyPart(part *multipart.Part, dir string) (string, string, error) {
	defer part.Close()

	tempFile, err := os.CreateTemp(dir, "yara-scan-*")
	if err != nil {
		return "", "", err
	}
	if err := copyUpload(tempFile, part); err != nil {
		tempFile.Close()
		os.Remove(tempFile.Name())
		return "", "", err
	}
	if err := tempFile.Close(); err != nil {
		os.Remove(tempFile.Name())
		return "", "", err
	}
	return tempFile.Name(), part.FileName(), nil
}

// copyUpload copies src to dst. Only src failures are classified as request
// errors; a dst failure (disk full, I/O error) stays a plain server error.
func copyUpload(dst io.Writer, src io.Reader) error {
	_, err := io.Copy(dst, readClassifier{src})
	return err
}

type readClassifier struct{ io.Reader }

func (r readClassifier) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if err != nil && err != io.EOF {
		err = classifyReadError(err)
	}
	return n, err
}

// classifyReadError keeps size-limit errors intact and marks any other
// body read failure as a malformed request.
func classifyReadError(err error) error {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		return err
	}
	return fmt.Errorf("%w: %v", errBadForm, err)
}

// handleHealth handles GET /health requests
func handleHealth(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"status":     "ok",
		"rules_path": config.RulesPath,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// sendError sends a JSON error response
// Note: message should be generic and not contain internal error details
func sendError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(ScanResponse{
		Error: message,
	})
}

func sendResponse(w http.ResponseWriter, response interface{}) {
	// Send JSON response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// sanitizeFilename removes potentially dangerous characters from filenames
// to prevent log injection attacks (newlines, carriage returns, control chars)
func sanitizeFilename(filename string) string {
	// Replace newlines and carriage returns with spaces
	safe := strings.ReplaceAll(filename, "\n", " ")
	safe = strings.ReplaceAll(safe, "\r", " ")

	// Remove other control characters (ASCII 0-31 except space)
	var result strings.Builder
	for _, r := range safe {
		if r >= 32 || r == '\t' {
			result.WriteRune(r)
		}
	}

	// Truncate overly long filenames
	const maxLen = 255
	if result.Len() > maxLen {
		return result.String()[:maxLen] + "..."
	}

	return result.String()
}
