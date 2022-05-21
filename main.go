package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"flag"
	"fmt"
	"log"
	"os"
)

var (
	fileName = flag.String("file", "", "file name")
	secret   = flag.String("secret", "", "secret")
)

func main() {
	flag.Parse()
	if *fileName == "" || *secret == "" {
		flag.PrintDefaults()
		return
	}

	fileBytes, err := os.ReadFile(*fileName)
	if err != nil {
		log.Fatal(err)
	}

	args := flag.Args()
	if len(args) > 0 && args[0] == "verify" {
		if verify(fileBytes, *secret) {
			fmt.Print("OK")
		} else {
			fmt.Print("FAIL")
		}
		return
	}

	h := hmac.New(sha256.New, []byte(*secret))

	n, err := h.Write(fileBytes)
	if n != len(fileBytes) {
		log.Fatal("write error")
	}

	if err != nil {
		log.Fatal(err)
	}

	if err := os.WriteFile(*fileName+".hmac", h.Sum(fileBytes), 0644); err != nil {
		log.Fatal(err)
	}
}

func verify(bytes []byte, secret string) bool {
	content := bytes[:len(bytes)-sha256.Size]
	mac := bytes[len(bytes)-sha256.Size:]

	h := hmac.New(sha256.New, []byte(secret))
	h.Write(content)
	return hmac.Equal(mac, h.Sum(nil))
}
