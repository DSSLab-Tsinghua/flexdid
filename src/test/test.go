package main

// a command line tool that generates the issuer's keys 

import (
	//"os"
	"path/filepath"

	//psidentity "psidentity"
	rpsidentity "psidentity/psidentity"
	//math "github.com/IBM/mathlib"
	"github.com/golang/protobuf/proto"
	//"github.com/stretchr/testify/require"

	//"psidentity/translator/amcl"
	"log"
	"fmt"
	"io/ioutil"
	"os"
	//"testing"
)

func main() {

	outputDir := "configidemix"
	//outputDir := "config"

	path := filepath.Join(outputDir, "issuer", "IssuerPublicKey")
	ipkBytes, _ := ioutil.ReadFile(path)

	ipk := &rpsidentity.IssuerPublicKey{}
	//ipk := &rpsidentity.IssuerPublicKeyPS{}
	log.Printf("ipkBytes is %v",ipkBytes)
	log.Printf("ipk address is %v",ipk)
	
	handleError(proto.Unmarshal(ipkBytes, ipk))
}

func handleError(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}