package git

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// Client handles git operations using a specific SSH key
type Client struct {
	PrivateKeyPath string
}

// New creates a new git client that will sign requests with the given private key
func New(privateKeyPath string) *Client {
	return &Client{
		PrivateKeyPath: privateKeyPath,
	}
}

// Pull fetches the latest changes for a specific branch
// Formerly: Update
func (c *Client) Pull(dir string, branch string) (int, error) {
	if branch == "" {
		branch = "main"
	}

	cmd := exec.Command("git", "pull", "origin", branch, "--ff-only")
	cmd.Dir = dir
	cmd.Env = c.generateSSHEnv()

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return 0, fmt.Errorf("could not pull latest changes: %v\nDetails: %s", err, stderr.String())
	}

	return countChangedFiles(stdout.String()), nil
}

// Clone downloads a repository to the specified destination
func (c *Client) Clone(repoURL, dist string) error {
	cmd := exec.Command("git", "clone", repoURL, dist)
	cmd.Env = c.generateSSHEnv()

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("could not clone repository: %v\nDetails: %s", err, stderr.String())
	}
	return nil
}

// Prepare ensures the repository exists locally; if not, it clones it.
// Formerly: EnsureRepo
func (c *Client) Prepare(repoURL, contentDir string) error {
	gitDir := fmt.Sprintf("%s/.git", contentDir)

	// If the .git directory exists, we assume the repo is ready
	if _, err := os.Stat(gitDir); !os.IsNotExist(err) {
		return nil
	}

	// It's missing, so we need to clone it using the SSH URL
	return c.Clone(ToSSH(repoURL), contentDir)
}

// ToSSH ensures the URL is in the correct git@github.com format
// Formerly: NormalizeURL
func ToSSH(url string) string {
	if !strings.HasPrefix(url, "http") {
		return url // Already SSH or unknown format
	}

	sshBase := "git@github.com"
	splitUrl := strings.Split(url, "/")
	if len(splitUrl) < 2 {
		return url
	}

	// Converts https://github.com/user/repo -> git@github.com:user/repo
	return fmt.Sprintf("%s:%s", sshBase, strings.Join(splitUrl[len(splitUrl)-2:], "/"))
}

// generateSSHEnv creates the environment variables to force git to use our specific key
func (c *Client) generateSSHEnv() []string {
	env := os.Environ()
	// StrictHostKeyChecking=accept-new is safe for CI/Automated environments
	sshCmd := fmt.Sprintf("ssh -i %s -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new", c.PrivateKeyPath)
	return append(env, "GIT_SSH_COMMAND="+sshCmd)
}

func countChangedFiles(output string) int {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasSuffix(line, "files changed") || strings.HasSuffix(line, "file changed") {
			parts := strings.Split(line, " ")
			if len(parts) > 0 {
				if n, err := strconv.Atoi(parts[0]); err == nil {
					return n
				}
			}
		}
	}
	return 0
}
