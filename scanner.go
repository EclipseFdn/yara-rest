package main

import (
	"archive/zip"
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// YARA-X binary path
const yaraBinary = "/usr/local/bin/yr"

// Scan temp directory - writable by any UID in GID 0 (OpenShift compatible)
const scanTempDir = "/tmp/scans"

// yaraXOutput represents a single line of YARA-X NDJSON output
type yaraXOutput struct {
	Path  string      `json:"path"`
	Rules []yaraXRule `json:"rules"`
}

// yaraXRule represents a matched rule in YARA-X output
type yaraXRule struct {
	Identifier string          `json:"identifier"`
	Namespace  string          `json:"namespace,omitempty"`
	Tags       []string        `json:"tags,omitempty"`
	Meta       [][]interface{} `json:"meta,omitempty"` // YARA-X outputs as [["key", value], ...]
	Patterns   []yaraXPattern  `json:"patterns,omitempty"`
}

// yaraXPattern represents a matched pattern/string
type yaraXPattern struct {
	Identifier string       `json:"identifier"`
	Matches    []yaraXMatch `json:"matches,omitempty"`
}

// yaraXMatch represents a single match location
type yaraXMatch struct {
	Offset int64  `json:"offset"`
	Length int    `json:"length"`
	Data   string `json:"data,omitempty"`
}

// Scanner handles YARA-X scanning operations
type Scanner struct {
	config *Config
}

// Match represents a single YARA-X rule match
type Match struct {
	Rule        string   `json:"rule"`
	File        string   `json:"file"`
	FileHash    string   `json:"file_hash,omitempty"` // SHA256 hash of matched file
	Severity    string   `json:"severity"`
	Tags        []string `json:"tags,omitempty"`
	Description string   `json:"description,omitempty"`
	Strings     []string `json:"strings,omitempty"`
}

// ScanResult holds the complete scan results
type ScanResult struct {
	Matches      []Match
	ScannedFiles int
}

// NewScanner creates a new YARA-X scanner
func NewScanner(config *Config) *Scanner {
	return &Scanner{
		config: config,
	}
}

// ScanFile scans a file with YARA-X rules.
// If the file is a ZIP archive, it extracts and scans all contents.
// Otherwise, it scans the single file directly.
func (s *Scanner) ScanFile(filePath string) (*ScanResult, error) {
	if s.config.DebugMode {
		log.Printf("ScanFile: starting scan of %s", filePath)
	}

	// Create temp directory for scanning
	// Uses scanTempDir which has OpenShift-compatible permissions (GID 0)
	tempDir, err := os.MkdirTemp(scanTempDir, "yara-extract-")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	// Try to extract as ZIP archive, fall back to single file scan
	fileCount, err := s.extractZipSafe(filePath, tempDir)
	if err != nil {
		// Check if it's just not a ZIP file (scan as single file)
		if isNotZipError(err) {
			if s.config.DebugMode {
				log.Printf("ScanFile: not a ZIP archive, scanning as single file")
			}
			fileCount, err = s.copySingleFile(filePath, tempDir)
			if err != nil {
				return nil, fmt.Errorf("failed to prepare file for scan: %w", err)
			}
		} else {
			return nil, fmt.Errorf("failed to extract archive: %w", err)
		}
	}

	if s.config.DebugMode {
		log.Printf("ScanFile: prepared %d file(s) for scanning", fileCount)
	}

	// Run YARA-X on extracted directory with timeout
	matches, err := s.runYara(tempDir)
	if err != nil {
		return nil, fmt.Errorf("YARA-X scan failed: %w", err)
	}

	if s.config.DebugMode {
		log.Printf("ScanFile: YARA-X found %d matches", len(matches))
	}

	// Compute file hashes and make paths relative
	for i := range matches {
		// Compute SHA256 hash of the matched file
		fullPath := matches[i].File
		hash, err := computeFileHash(fullPath)
		if err != nil {
			if s.config.DebugMode {
				log.Printf("Warning: could not compute hash for %s: %v", fullPath, err)
			}
		} else {
			matches[i].FileHash = hash
		}

		// Make path relative to extraction root
		matches[i].File = strings.TrimPrefix(fullPath, tempDir+string(os.PathSeparator))
	}

	return &ScanResult{
		Matches:      matches,
		ScannedFiles: fileCount,
	}, nil
}

// computeFileHash computes the SHA256 hash of a file
func computeFileHash(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// runYara executes YARA-X on a directory and parses JSON output
func (s *Scanner) runYara(targetDir string) ([]Match, error) {
	// Find all .yar files in rules directory
	ruleFiles, err := s.findRuleFiles()
	if err != nil {
		return nil, err
	}

	if len(ruleFiles) == 0 {
		return nil, fmt.Errorf("no .yar files found in %s", s.config.RulesPath)
	}

	if s.config.DebugMode {
		log.Printf("Found %d rule file(s)", len(ruleFiles))
	}

	// Build YARA-X command: yr scan [OPTIONS] <RULES_PATH>... <TARGET_PATH>
	// --output-format=ndjson: JSON output (one JSON object per line)
	// -m: include metadata (severity, description)
	// -g: include tags
	// --recursive: scan target directory recursively (with optional depth limit)
	args := []string{"scan", "--output-format=ndjson", "-m", "-g"}

	// Add recursive flag with optional depth limit
	if s.config.MaxScanDepth > 0 {
		args = append(args, fmt.Sprintf("--recursive=%d", s.config.MaxScanDepth))
	} else {
		args = append(args, "--recursive")
	}
	args = append(args, ruleFiles...)
	args = append(args, targetDir)

	if s.config.DebugMode {
		log.Printf("Running: %s %v", yaraBinary, args)
	}

	// Create context with timeout for the scan
	ctx, cancel := context.WithTimeout(context.Background(), s.config.ScanTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, yaraBinary, args...)

	output, err := cmd.CombinedOutput()

	// Check for timeout
	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("YARA-X scan timed out after %v", s.config.ScanTimeout)
	}

	if s.config.DebugMode {
		log.Printf("YARA-X finished. output=%d bytes, err=%v", len(output), err)
		if len(output) > 0 {
			preview := string(output)
			if len(preview) > 500 {
				preview = preview[:500] + "..."
			}
			log.Printf("YARA-X output: %s", preview)
		}
	}

	// Handle errors (but YARA-X may output matches even with non-zero exit)
	if err != nil {
		// If we have JSON output, try to parse it first
		if len(output) > 0 && output[0] == '{' {
			matches, parseErr := parseYaraXOutput(output)
			if parseErr == nil {
				return matches, nil
			}
		}

		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("YARA-X error (exit %d): %s", exitErr.ExitCode(), string(output))
		}
		return nil, fmt.Errorf("YARA-X error: %v", err)
	}

	// Parse NDJSON output
	if len(output) == 0 {
		return []Match{}, nil
	}

	matches, err := parseYaraXOutput(output)
	if err != nil {
		return nil, fmt.Errorf("failed to parse YARA-X output: %w", err)
	}

	if s.config.DebugMode {
		log.Printf("Parsed %d matches from YARA-X output", len(matches))
	}

	return matches, nil
}

// findRuleFiles finds all .yar files in the rules directory
func (s *Scanner) findRuleFiles() ([]string, error) {
	var files []string

	err := filepath.Walk(s.config.RulesPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && (strings.HasSuffix(path, ".yar") || strings.HasSuffix(path, ".yara")) {
			files = append(files, path)
		}
		return nil
	})

	return files, err
}

// parseYaraXOutput parses YARA-X NDJSON output into Match structs.
// Each line is a JSON object with path and matched rules.
func parseYaraXOutput(output []byte) ([]Match, error) {
	var matches []Match

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var result yaraXOutput
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			// Skip lines that aren't valid JSON (e.g., warnings)
			continue
		}

		// Convert each matched rule to our Match format
		for _, rule := range result.Rules {
			match := Match{
				Rule:     rule.Identifier,
				File:     result.Path,
				Tags:     rule.Tags,
				Severity: "HIGH", // Default
			}

			// Extract metadata (severity, description)
			// YARA-X outputs meta as array of [key, value] pairs
			for _, meta := range rule.Meta {
				if len(meta) < 2 {
					continue
				}
				key, ok := meta[0].(string)
				if !ok {
					continue
				}
				value := fmt.Sprintf("%v", meta[1])

				switch strings.ToLower(key) {
				case "severity":
					match.Severity = strings.ToUpper(value)
				case "description":
					match.Description = value
				}
			}

			// Extract matched strings from patterns
			for _, pattern := range rule.Patterns {
				for _, m := range pattern.Matches {
					if m.Data != "" {
						match.Strings = append(match.Strings, m.Data)
					}
				}
			}

			matches = append(matches, match)
		}
	}

	return matches, scanner.Err()
}

// extractZipSafe extracts a ZIP file with zip bomb protection.
// Returns the number of files extracted.
//
// Security measures:
// - Limits total extracted size to prevent disk exhaustion
// - Limits number of files to prevent inode exhaustion
// - Limits individual file size
// - Prevents zip slip attacks (path traversal)
func (s *Scanner) extractZipSafe(zipPath, targetDir string) (int, error) {
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return 0, err
	}
	defer reader.Close()

	fileCount := 0
	totalSize := int64(0)

	for _, file := range reader.File {
		// Check file count limit
		fileCount++
		if fileCount > s.config.MaxFileCount {
			return 0, fmt.Errorf("archive contains too many files (limit: %d)", s.config.MaxFileCount)
		}

		// Check individual file size limit (from header)
		if file.UncompressedSize64 > s.config.MaxSingleFileSize {
			return 0, fmt.Errorf("file %s exceeds size limit (%d > %d bytes)",
				file.Name, file.UncompressedSize64, s.config.MaxSingleFileSize)
		}

		// Check total extracted size (using header info)
		totalSize += int64(file.UncompressedSize64)
		if totalSize > s.config.MaxExtractedSize {
			return 0, fmt.Errorf("archive exceeds total size limit (%d bytes)", s.config.MaxExtractedSize)
		}

		// Build target path
		targetPath := filepath.Join(targetDir, file.Name)

		// Security check: prevent zip slip attack
		if !strings.HasPrefix(targetPath, filepath.Clean(targetDir)+string(os.PathSeparator)) {
			continue // Skip files that would escape target directory
		}

		if file.FileInfo().IsDir() {
			os.MkdirAll(targetPath, 0755)
			continue
		}

		// Create parent directories
		if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
			return fileCount, err
		}

		// Extract file with size limit enforcement
		if err := s.extractFileSafe(file, targetPath); err != nil {
			return fileCount, err
		}
	}

	return fileCount, nil
}

// extractFileSafe extracts a single file from the ZIP with size limit enforcement.
// This provides runtime protection against deceptive header sizes.
func (s *Scanner) extractFileSafe(file *zip.File, targetPath string) error {
	src, err := file.Open()
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.Create(targetPath)
	if err != nil {
		return err
	}
	defer dst.Close()

	// Use LimitReader to enforce size limit during extraction
	// This protects against archives with false header sizes
	limitedReader := io.LimitReader(src, int64(s.config.MaxSingleFileSize)+1)

	written, err := io.Copy(dst, limitedReader)
	if err != nil {
		return err
	}

	// Check if we hit the limit (file was larger than allowed)
	if written > int64(s.config.MaxSingleFileSize) {
		os.Remove(targetPath) // Clean up partial file
		return fmt.Errorf("file %s exceeded size limit during extraction", file.Name)
	}

	return nil
}

// isNotZipError checks if the error indicates the file is not a valid ZIP archive.
// Used to distinguish between "not a ZIP" and actual extraction errors.
func isNotZipError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "zip: not a valid zip file") ||
		strings.Contains(errStr, "unexpected EOF")
}

// copySingleFile copies a non-archive file to the temp directory for scanning.
// Enforces size limits and returns file count (always 1 on success).
func (s *Scanner) copySingleFile(srcPath, targetDir string) (int, error) {
	// Check file size before copying
	info, err := os.Stat(srcPath)
	if err != nil {
		return 0, fmt.Errorf("failed to stat file: %w", err)
	}

	if uint64(info.Size()) > s.config.MaxSingleFileSize {
		return 0, fmt.Errorf("file exceeds size limit (%d > %d bytes)",
			info.Size(), s.config.MaxSingleFileSize)
	}

	// Open source file
	src, err := os.Open(srcPath)
	if err != nil {
		return 0, fmt.Errorf("failed to open file: %w", err)
	}
	defer src.Close()

	// Create destination file in temp directory
	dstPath := filepath.Join(targetDir, filepath.Base(srcPath))
	dst, err := os.Create(dstPath)
	if err != nil {
		return 0, fmt.Errorf("failed to create temp file: %w", err)
	}
	defer dst.Close()

	// Copy with size limit enforcement
	limitedReader := io.LimitReader(src, int64(s.config.MaxSingleFileSize)+1)
	written, err := io.Copy(dst, limitedReader)
	if err != nil {
		return 0, fmt.Errorf("failed to copy file: %w", err)
	}

	// Verify size limit wasn't exceeded during copy
	if written > int64(s.config.MaxSingleFileSize) {
		os.Remove(dstPath)
		return 0, fmt.Errorf("file exceeded size limit during copy")
	}

	return 1, nil
}
