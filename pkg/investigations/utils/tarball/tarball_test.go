package tarball

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreateTarball(t *testing.T) {
	tests := []struct {
		name          string
		setupDir      func(t *testing.T) string // Returns path to source directory
		wantErr       bool
		wantFiles     []string // Expected files in tarball (relative paths)
		wantFileCount int      // Expected number of entries
		description   string
	}{
		{
			name: "simple directory with files",
			setupDir: func(t *testing.T) string {
				t.Helper()
				dir := t.TempDir()
				// Create test files
				writeFile(t, filepath.Join(dir, "file1.txt"), "content1")
				writeFile(t, filepath.Join(dir, "file2.txt"), "content2")
				return dir
			},
			wantErr: false,
			wantFiles: []string{
				"file1.txt",
				"file2.txt",
			},
			wantFileCount: 2,
			description:   "Should create tarball with all files from flat directory",
		},
		{
			name: "nested directory structure",
			setupDir: func(t *testing.T) string {
				t.Helper()
				dir := t.TempDir()
				// Create nested structure
				writeFile(t, filepath.Join(dir, "root.txt"), "root content")
				_ = os.MkdirAll(filepath.Join(dir, "subdir1"), 0o750)
				writeFile(t, filepath.Join(dir, "subdir1", "file1.txt"), "sub1 content")
				_ = os.MkdirAll(filepath.Join(dir, "subdir1", "nested"), 0o750)
				writeFile(t, filepath.Join(dir, "subdir1", "nested", "deep.txt"), "deep content")
				_ = os.MkdirAll(filepath.Join(dir, "subdir2"), 0o750)
				writeFile(t, filepath.Join(dir, "subdir2", "file2.txt"), "sub2 content")
				return dir
			},
			wantErr: false,
			wantFiles: []string{
				"root.txt",
				"subdir1",
				"subdir1/file1.txt",
				"subdir1/nested",
				"subdir1/nested/deep.txt",
				"subdir2",
				"subdir2/file2.txt",
			},
			wantFileCount: 7, // 3 files + 3 directories + root content
			description:   "Should preserve nested directory structure in tarball",
		},
		{
			name: "empty directory",
			setupDir: func(t *testing.T) string {
				t.Helper()
				return t.TempDir() // Empty directory
			},
			wantErr:       false,
			wantFiles:     []string{},
			wantFileCount: 0,
			description:   "Should create valid tarball for empty directory",
		},
		{
			name: "directory with only subdirectories",
			setupDir: func(t *testing.T) string {
				t.Helper()
				dir := t.TempDir()
				_ = os.MkdirAll(filepath.Join(dir, "empty1"), 0o750)
				_ = os.MkdirAll(filepath.Join(dir, "empty2"), 0o750)
				return dir
			},
			wantErr: false,
			wantFiles: []string{
				"empty1",
				"empty2",
			},
			wantFileCount: 2,
			description:   "Should include empty directories in tarball",
		},
		{
			name: "large file",
			setupDir: func(t *testing.T) string {
				t.Helper()
				dir := t.TempDir()
				// Create a 1MB file
				writeFile(t, filepath.Join(dir, "large.bin"), strings.Repeat("A", 1024*1024))
				return dir
			},
			wantErr: false,
			wantFiles: []string{
				"large.bin",
			},
			wantFileCount: 1,
			description:   "Should handle large files correctly",
		},
		{
			name: "files with special characters in names",
			setupDir: func(t *testing.T) string {
				t.Helper()
				dir := t.TempDir()
				writeFile(t, filepath.Join(dir, "file with spaces.txt"), "content")
				writeFile(t, filepath.Join(dir, "file-with-dashes.txt"), "content")
				writeFile(t, filepath.Join(dir, "file_with_underscores.txt"), "content")
				return dir
			},
			wantErr: false,
			wantFiles: []string{
				"file with spaces.txt",
				"file-with-dashes.txt",
				"file_with_underscores.txt",
			},
			wantFileCount: 3,
			description:   "Should handle special characters in filenames",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sourceDir := tt.setupDir(t)

			// Create temporary tarball file
			tarballFile, err := os.CreateTemp("", "test-*.tar.gz")
			if err != nil {
				t.Fatalf("Failed to create temp tarball file: %v", err)
			}
			defer func() { _ = os.Remove(tarballFile.Name()) }()
			defer func() { _ = tarballFile.Close() }()

			// Create the tarball
			err = CreateTarball(sourceDir, tarballFile)

			// Check error expectation
			if tt.wantErr {
				if err == nil {
					t.Errorf("%s: expected error but got none", tt.description)
				}
				return
			}

			if err != nil {
				t.Errorf("%s: unexpected error: %v", tt.description, err)
				return
			}

			// Close and reopen for reading
			_ = tarballFile.Close()

			// Verify tarball contents
			entries, err := extractTarballEntries(tarballFile.Name())
			if err != nil {
				t.Errorf("%s: failed to read tarball: %v", tt.description, err)
				return
			}

			// Check entry count
			if len(entries) != tt.wantFileCount {
				t.Errorf("%s: expected %d entries, got %d. Entries: %v",
					tt.description, tt.wantFileCount, len(entries), entries)
			}

			// Check that expected files are present
			entryMap := make(map[string]bool)
			for _, entry := range entries {
				entryMap[entry] = true
			}

			for _, wantFile := range tt.wantFiles {
				if !entryMap[wantFile] {
					t.Errorf("%s: expected file %q not found in tarball. Got: %v",
						tt.description, wantFile, entries)
				}
			}
		})
	}
}

func TestCreateTarballErrors(t *testing.T) {
	tests := []struct {
		name        string
		setupDir    func(t *testing.T) string
		wantErr     bool
		description string
	}{
		{
			name: "non-existent directory",
			setupDir: func(t *testing.T) string {
				t.Helper()
				return "/nonexistent/path/that/does/not/exist"
			},
			wantErr:     true,
			description: "Should return error for non-existent directory",
		},
		{
			name: "file instead of directory",
			setupDir: func(t *testing.T) string {
				t.Helper()
				dir := t.TempDir()
				filePath := filepath.Join(dir, "notadir.txt")
				writeFile(t, filePath, "content")
				return filePath
			},
			wantErr:     false, // filepath.Walk handles files as directories with single entry
			description: "Should handle file path (walks single file)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sourceDir := tt.setupDir(t)

			tarballFile, err := os.CreateTemp("", "test-error-*.tar.gz")
			if err != nil {
				t.Fatalf("Failed to create temp tarball file: %v", err)
			}
			defer func() { _ = os.Remove(tarballFile.Name()) }()
			defer func() { _ = tarballFile.Close() }()

			err = CreateTarball(sourceDir, tarballFile)

			if tt.wantErr && err == nil {
				t.Errorf("%s: expected error but got none", tt.description)
			}

			if !tt.wantErr && err != nil {
				t.Errorf("%s: unexpected error: %v", tt.description, err)
			}
		})
	}
}

func TestCreateTarballContentVerification(t *testing.T) {
	// Create a test directory with known content
	dir := t.TempDir()
	expectedContent := map[string]string{
		"file1.txt":             "Hello World",
		"subdir/file2.txt":      "Nested content",
		"subdir/deep/file3.txt": "Deep nested content",
	}

	for path, content := range expectedContent {
		fullPath := filepath.Join(dir, path)
		_ = os.MkdirAll(filepath.Dir(fullPath), 0o750)
		writeFile(t, fullPath, content)
	}

	// Create tarball
	tarballFile, err := os.CreateTemp("", "test-content-*.tar.gz")
	if err != nil {
		t.Fatalf("Failed to create temp tarball file: %v", err)
	}
	defer func() { _ = os.Remove(tarballFile.Name()) }()
	defer func() { _ = tarballFile.Close() }()

	err = CreateTarball(dir, tarballFile)
	if err != nil {
		t.Fatalf("Failed to create tarball: %v", err)
	}

	_ = tarballFile.Close()

	// Extract and verify content
	actualContent, err := extractTarballContent(tarballFile.Name())
	if err != nil {
		t.Fatalf("Failed to extract tarball: %v", err)
	}

	// Verify all expected files have correct content
	for path, expectedText := range expectedContent {
		actualText, found := actualContent[path]
		if !found {
			t.Errorf("Expected file %q not found in tarball", path)
			continue
		}

		if actualText != expectedText {
			t.Errorf("File %q content mismatch.\nExpected: %q\nGot: %q",
				path, expectedText, actualText)
		}
	}
}

// Helper functions

func writeFile(t *testing.T, path string, content string) {
	t.Helper()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("Failed to create directory %s: %v", dir, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("Failed to write file %s: %v", path, err)
	}
}

func extractTarballEntries(tarballPath string) ([]string, error) {
	file, err := os.Open(tarballPath) // #nosec G304 -- tarballPath is test-generated temp file
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return nil, err
	}
	defer func() { _ = gzipReader.Close() }()

	tarReader := tar.NewReader(gzipReader)

	var entries []string
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		entries = append(entries, header.Name)
	}

	return entries, nil
}

func extractTarballContent(tarballPath string) (map[string]string, error) {
	file, err := os.Open(tarballPath) // #nosec G304 -- tarballPath is test-generated temp file
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return nil, err
	}
	defer func() { _ = gzipReader.Close() }()

	tarReader := tar.NewReader(gzipReader)

	content := make(map[string]string)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		// Only read content of regular files
		if header.Typeflag == tar.TypeReg {
			data, err := io.ReadAll(tarReader)
			if err != nil {
				return nil, err
			}
			content[header.Name] = string(data)
		}
	}

	return content, nil
}
