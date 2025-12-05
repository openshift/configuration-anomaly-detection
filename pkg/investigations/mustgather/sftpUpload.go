package mustgather

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
)

const (
	// RED HAT SFTP server configuration, see https://access.redhat.com/articles/5594481
	redhatSftpTokenUrl                     = "https://access.redhat.com/hydra/rest/v2/sftp/token" // #nosec G101 the URL for requesting username and token for temporary anonymous access to upload files to the RED HAT SFTP server
	redhatSftpServerUrlAndPort             = "sftp.access.redhat.com:22"                          // the connection string for connecting to the RED HAT SFTP server
	redhatSftpServerSslExpectedFingerprint = "SHA256:Ij7dPhl1PhiycLC/rFXy1sGO2nSS9ky0PYdYhi+ykpQ" // the SSL certificate fingerprint, taken from here: https://access.redhat.com/articles/5594481#TOC36
)

// HTTPDoer interface allows mocking HTTP clients for testing
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type sftpTokenRequest struct {
	IsAnonymous bool `json:"isAnonymous"`
}

type sftpTokenResponse struct {
	Username   string `json:"username"`
	Token      string `json:"token"`
	ExpiryDate string `json:"expiryDate"`
}

// sftpUpload implements uploading to the Red Hat SFTP server according to this article https://access.redhat.com/articles/5594481
func sftpUpload(ctx context.Context, fileName string, username string, token string) error {
	// Check if context is already cancelled before starting
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context cancelled before SFTP upload: %w", err)
	}

	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(token),
		},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			fingerprint := ssh.FingerprintSHA256(key)
			if fingerprint != redhatSftpServerSslExpectedFingerprint {
				return fmt.Errorf("SSH: host key fingerprint mismatch. got %s, want %s", fingerprint, redhatSftpServerSslExpectedFingerprint)
			}
			return nil
		},
		Timeout: 30 * time.Second, // Connection timeout
	}

	conn, err := ssh.Dial("tcp", redhatSftpServerUrlAndPort, config)
	if err != nil {
		return fmt.Errorf("failed to dial SSH server: %w", err)
	}
	defer func() {
		err := conn.Close()
		if err != nil {
			logging.Errorf("Failed to close SSH connection: %v", err)
		}
	}()

	client, err := sftp.NewClient(conn)
	if err != nil {
		return fmt.Errorf("failed to create SFTP client: %w", err)
	}
	defer func() {
		err := client.Close()
		if err != nil {
			logging.Errorf("Failed to close SFTP client: %v", err)
		}
	}()

	localFile, err := os.Open(filepath.Clean(fileName))
	if err != nil {
		return fmt.Errorf("failed to open local file that was opened for SFTP upload %s: %w", fileName, err)
	}
	defer func() {
		err := localFile.Close()
		if err != nil {
			logging.Errorf("Failed to close local file that was opened for SFTP upload: %v", err)
		}
	}()

	remoteFileName := path.Base(fileName)
	// RH SFTP does not support opening the file in both READ and WRITE mode, we therefore cannot use client.Create()
	dstFile, err := client.OpenFile(remoteFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return fmt.Errorf("failed to create remote SFTP target file %s: %w", remoteFileName, err)
	}
	defer func() {
		err := dstFile.Close()
		if err != nil {
			logging.Errorf("failed to close remote SFTP target file : %v", err)
		}
	}()

	// Copy with context awareness - this is the slow operation that needs the timeout
	n, err := copyWithContext(ctx, dstFile, localFile)
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("SFTP upload cancelled: %w", ctx.Err())
		}
		return fmt.Errorf("failed to copy file to remote server: %w", err)
	}
	logging.Infof("Successfully uploaded %d bytes to SFTP server", n)

	return nil
}

// getAnonymousSftpCredentials fetches username and token for uploading to Red Hat SFTP according to this article https://access.redhat.com/articles/5594481
func getAnonymousSftpCredentials(ctx context.Context, client HTTPDoer) (string, string, error) {
	jsonData, err := json.Marshal(sftpTokenRequest{IsAnonymous: true})
	if err != nil {
		return "", "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, redhatSftpTokenUrl, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", "", err
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}

	defer func() {
		err := resp.Body.Close()
		if err != nil {
			logging.Errorf("failed to close SFTP credential POST response body: %v", err)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("SFTP credential request failed with status %s: %s", resp.Status, string(body))
	}

	var parsedResponse sftpTokenResponse

	if err := json.Unmarshal(body, &parsedResponse); err != nil {
		return "", "", err
	}

	return parsedResponse.Username, parsedResponse.Token, nil
}

// copyWithContext copies data from src to dst while respecting context cancellation.
// It checks the context between each chunk to allow graceful cancellation.
func copyWithContext(ctx context.Context, dst io.Writer, src io.Reader) (int64, error) {
	buf := make([]byte, 128*1024) // 128KB chunks
	var written int64

	for {
		// Check context before each chunk
		select {
		case <-ctx.Done():
			return written, ctx.Err()
		default:
		}

		nr, readErr := src.Read(buf)
		if nr > 0 {
			nw, writeErr := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if writeErr != nil {
				return written, writeErr
			}
			if nr != nw {
				return written, io.ErrShortWrite
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				break
			}
			return written, readErr
		}
	}
	return written, nil
}
