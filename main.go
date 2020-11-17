package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/kondor6c/checkr_certs/pkg/pki"
)

func main() {
	var optCertIn string
	opts := gatherOpts()
	dat := decideRoute(opts)
	pki.Init()
	if opts.ActionSecondary == "debug" {
		pki.DebugSet = true
	}
	if opts.ActionPrimary == "web-ui" || opts.ActionPrimary == "web-server" {
		mux := http.NewServeMux()
		mux.HandleFunc("/", dat.MainHandler)
		mux.HandleFunc("/add", dat.AddHandler)
		mux.HandleFunc("/view", dat.ViewHandler)
		mux.HandleFunc("/view/ical", dat.IcalHandler)
		mux.HandleFunc("/view/cert", dat.ServePemHandler)
		mux.HandleFunc("/api", dat.RespondJSONHandler)
		mux.HandleFunc("/api/cert", dat.X509CertHandler)
		mux.HandleFunc("/api/cert/remote", dat.RemoteURLHandler)
		mux.HandleFunc("/api/key", dat.PrivateKeyHandler)
		mux.HandleFunc("/edit", dat.EditHandler)
		mux.HandleFunc("/fetch", dat.FetchHandler)
		http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
		log.Fatal(http.ListenAndServe(":5000", mux))
	}
	fmt.Println(optCertIn)
}

func gatherOpts() pki.ConfigStore {
	/* option ideas: output format (ie json, text, template),
	   check inputs (check key belongs to cert if both passed otherwise just check cert, or check rsa pubkey),
	   env read from env vars,
	   AIO cert, ca chain, and key are all in one file/env
	*/
	opt := &pki.ConfigStore{}
	//optMap := make(map[string]string)
	//flag := flag.NewFlagSet("output", flag.ContinueOnError)
	flag.StringVar(&opt.CertIn, "cert-in", "None", "certificate input source")
	flag.StringVar(&opt.CaIn, "ca-in", "None", "issuing certificate authority for cert")
	flag.StringVar(&opt.KeyIn, "key-in", "None", "key input source")
	flag.StringVar(&opt.ActionPrimary, "action", "None", "Primary action")
	flag.StringVar(&opt.ActionSecondary, "subAction", "None", "Secondary action")
	flag.StringVar(&opt.CertIn, "key-out", "None", "certificate")
	flag.StringVar(&opt.KeyOut, "ca-out", "None", "issuing certificate authority for cert")
	flag.StringVar(&opt.CertOut, "cert-out", "None", "key for certificate")
	//flagSet.Var(&optMap["List"], "None", "list of options to pass delimiter ',' [not implemented]")
	flag.StringVar(&opt.CaOut, "CA-out", "None", "action to take")
	flag.Parse()
	if pki.DebugSet == true {
		log.Printf("obtained arguments: %s", os.Args)
	}
	if flag.NFlag() < 1 && os.Stdin == nil {
		flag.PrintDefaults()
	}
	return *opt
}

// decideRoute send a command to the correct function according to options
func decideRoute(c pki.ConfigStore) *pki.PrivateData {
	curAction := &pki.PrivateData{}
	//cliFiles := []string{c.CertIn, c.KeyIn, c.CaIn}
	if c.ActionPrimary == "web-ui" {
		curAction.MainAction = "web-ui"
		// } else if curAction.mainAction == "ca-check" && len(curAction.auth.ca) >= 1 {
		// } else if curAction.mainAction == "trust-check" && len(curAction.auth.ca) >= 1 {

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
