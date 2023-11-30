package encryption

import (
	"io"
	"os"
	"path/filepath"
)

// reverseString reverses a string.
func reverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

// copyFile copies a file from src to dst.
func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	return err
}

// copyAndReverseName copies a file and reverses its name.
func CopyAndReverseName(src, dstDir string) (string, error) {
	base := filepath.Base(src)
	reversedBase := reverseString(base)
	dst := filepath.Join(dstDir, reversedBase)

	err := copyFile(src, dst)
	if err != nil {
		return "", err
	}

	return dst, nil
}
