package cmd

import (
	"io"
	"log"
	"os"
)

// decideRoute send a command to the correct function according to options
func decideRoute(c configStore) *PrivateData {
	curAction := &PrivateData{}
	cliFiles := []string{c.CertIn, c.KeyIn, c.CaIn}
	for _, i := range cliFiles {
		if i == "None" {
			continue
		}
		pemData := pki.pemFile(fileOpen(i))
		curAction.addPem(pemData)
	}
	if curAction.key != nil && curAction.mainAction == "copy" { //I still do not know how to check if x509.Certificate is not nil, (anonymous struct?)
		//curAction.cert.CheckSignature(//checkSig see if key matches cert
		curAction.req = copyCert(curAction.cert)
		//curAction.keyPairReq()
	} else if curAction.key != nil && curAction.mainAction == "gen-template" {

	} else if curAction.mainAction == "edit-csr" {
	} else if c.ActionPrimary == "web-ui" {
		curAction.mainAction = "web-ui"
	} else if curAction.mainAction == "ca-check" && len(curAction.auth.ca) >= 1 {
	} else if curAction.mainAction == "trust-check" && len(curAction.auth.ca) >= 1 {

	} else if curAction.mode == "remote-pull" {

	}
	return curAction
}

func fileOpen(filename string) io.Reader {
	_, err := os.Stat(filename)
	var fileRead io.Reader
	var oerr error
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("The file specified '%v' does not exist", filename)
		} else if os.IsPermission(err) {
			log.Printf("Unable to read file '%v' due to permissions", filename)
		} else {
			log.Printf("a general has occurred on file '%v', it is likely file related", filename)
			panic(err)
		}
	} else {
		fileRead, oerr = os.Open(filename)
		if oerr != nil {
			log.Fatal(oerr)
		}
		// defer fileRead.Close() //I made this as an io.Reader above, do I need to close it??
	}
	return fileRead
}
