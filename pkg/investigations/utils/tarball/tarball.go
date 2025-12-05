package tarball

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
)

// CreateTarball creates a compressed tarball archive from a source directory.
// It expects a source directory to be included into the tar, and an open file descriptor for writing the tar.
func CreateTarball(sourceDir string, tarballFile *os.File) error {
	gzipWriter := gzip.NewWriter(tarballFile)
	defer func() {
		err := gzipWriter.Close()
		if err != nil {
			logging.Errorf("Failed to close gzipWriter: %v", err)
		}
	}()

	tarWriter := tar.NewWriter(gzipWriter)
	defer func() {
		err := tarWriter.Close()
		if err != nil {
			logging.Errorf("Failed to close the tar writer: %v", err)
		}
	}()

	// Walk through the directory and add files to the tarball
	err := filepath.Walk(sourceDir, func(file string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("error walking the path %v: %w", file, err)
		}

		// Skip the root directory itself
		if file == sourceDir {
			return nil
		}

		// Create the header for the file entry
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return fmt.Errorf("failed to create tar header for file %v: %w", file, err)
		}

		// Set the relative name for the file in the tarball (strip the sourceDir prefix)
		relPath, err := filepath.Rel(sourceDir, file)
		if err != nil {
			return fmt.Errorf("failed to get relative path: %w", err)
		}
		header.Name = relPath

		// Write the header for the file into the tarball
		err = tarWriter.WriteHeader(header)
		if err != nil {
			return fmt.Errorf("failed to write header for file %v: %w", file, err)
		}

		// Skip, if it's not a regular file
		if !info.Mode().IsRegular() {
			return nil
		}

		fileToArchive, err := os.Open(filepath.Clean(file))
		if err != nil {
			return fmt.Errorf("failed to open file %v: %w", file, err)
		}
		defer func() {
			err := fileToArchive.Close()
			if err != nil {
				logging.Errorf("Failed to close the tar archive file: %v", err)
			}
		}()

		// Copy the file content into the tarball
		_, err = io.Copy(tarWriter, fileToArchive)
		if err != nil {
			return fmt.Errorf("failed to write file content for file %v: %w", file, err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("error walking source directory: %w", err)
	}

	return nil
}
