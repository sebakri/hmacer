package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"flag"
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

	h := hmac.New(sha256.New, []byte(*secret))

	n, err := h.Write(fileBytes)
	if n != len(fileBytes) {
		log.Fatal("write error")
	}

	if err != nil {
		log.Fatal(err)
	}

	if err := os.WriteFile(*fileName+".hmac", h.Sum(nil), 0644); err != nil {
		log.Fatal(err)
	}
}
