package utils

import (
	"crypto/rand"
	"io"
)

func CreateOtp(size int) (string, error) {
	b := make([]byte, size)
	n, err := io.ReadAtLeast(rand.Reader, b, size)
	if n != size {
		return "", err
	}
	for i := 0; i < len(b); i++ {
		b[i] = table[int(b[i])%len(table)]
	}
	return string(b), nil
}

var table = [...]byte{'1', '2', '3', '4', '5', '6', '7', '8', '9', '0'}
