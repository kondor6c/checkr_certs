package pki

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"fmt" //TODO remove entirely, I believe this is "code smell"
	"html/template"
	"log"
	"net/http"

	"github.com/kondor6c/checkr_certs/internal/web"
)

func (p *PrivateData) ServePemHandler(w http.ResponseWriter, r *http.Request) {

	pemBytes := toPem(p.cert)
	w.Header().Set("Content-Type", "text/plain")
	//w.Header().Set("Content-Disposition", "attachment; filename=file.pem")
	w.Write(pemBytes)
}

func (p *PrivateData) IcalHandler(w http.ResponseWriter, r *http.Request) {
	iCal := new(bytes.Buffer)
	templatePage, _ := template.New("Request").Parse(web.ICalExpire)
	templatePage.Execute(iCal, p)
	w.Header().Set("Content-Disposition", "attachment; filename=certificate-expiration.ics")
	//w.Header().Set("Content-Type", r.Header.Get("Content-Type"))
	w.Write(iCal.Bytes())

	//http.ServeFile(w, r, "certificate-expiration.ical", iCal)
}

func (p *PrivateData) ViewHandler(w http.ResponseWriter, r *http.Request) {
	var pageBody string
	var certPubKey rsa.PublicKey
	//var PubKey rsa.PublicKey
	var publicKey *rsa.PublicKey
	//certPubKey = p.cert.PublicKey.(*rsa.PublicKey)
	htmlColor := "red"
	// var htmlColor string
	if p.cert.Signature != nil {
		publicKey = p.cert.PublicKey.(*rsa.PublicKey)
		keyDigest := GetPublicKeyDigest(*publicKey)
		certRow := fmt.Sprintf("<TR><TD><A HREF='/edit'>%s</A></TD><TD>%s</TD><TD>%s</TD><TD>%s</TD><TD>%s</TD><TD>%s</TD><TD>%s</TD><TD><A HREF='/view/ical'>%s</A></TD><TD>%s</TD></TR>\n</TABLE>", p.cert.Subject.CommonName, p.cert.Subject.Locality, p.cert.Subject.Organization, p.cert.Subject.OrganizationalUnit, p.cert.Subject.ExtraNames, p.cert.Issuer, p.cert.DNSNames, p.cert.NotAfter, keyDigest)
		pageBody = fmt.Sprintf("%s\n%s\n%s\n", pageBody, web.CertView, certRow)
	}
	if p.key != nil {
		privKey := p.key.(*rsa.PrivateKey)
		privKeyDigest := GetPublicKeyDigest(privKey.PublicKey)
		if bytes.Compare(privKeyDigest, GetPublicKeyDigest(certPubKey)) == 0 {
			htmlColor = "green"
		}

		keyRow := fmt.Sprintf("<TR><TD>TBA</TD><TD>%d</TD><TD>NA (yet)</TD><TD style='background-color:%s'>%s</TD></TR>\n</TABLE>", privKey.PublicKey.N.BitLen(), htmlColor, privKeyDigest)
		pageBody = fmt.Sprintf("%s\n%s\n%s", pageBody, web.KeyView, keyRow)
		log.Println("Private Key public Modulus bytes md5")
		log.Println(privKeyDigest)
	}
	joinedPage := fmt.Sprintf("%s\n%s\n%s", web.HtmlHead, pageBody, web.HtmlFoot)
	templatePage, _ := template.New("Request").Parse(joinedPage)
	templatePage.Execute(w, p.cert)
}

func (p *PrivateData) MainHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)

}
func (p *PrivateData) formHandler(w http.ResponseWriter, r *http.Request) {
	pageConfig := &ConfigStore{ActionChoices: []string{"cert", "csr", "key", "ca"}}
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	joinedPage := fmt.Sprintf("%s\n%s\n%s", web.HtmlHead, web.MainPage, web.HtmlFoot)
	templatePage, _ := template.New("Request").Parse(joinedPage)
	templatePage.Execute(w, pageConfig)
}

func (p *PrivateData) FetchHandler(w http.ResponseWriter, r *http.Request) {
	rCert := fetchRemoteCert("tcp", r.FormValue("rAddress"), r.FormValue("rPort"))

	//verifiedRemoteChain := getChain(rCert)
	p.cert = *rCert[0] //dereference
	log.Printf("Fetched remote %s \n", r.FormValue("rAddress"))
	http.Redirect(w, r, "/view", http.StatusTemporaryRedirect)

}

func (p *PrivateData) EditHandler(w http.ResponseWriter, r *http.Request) {
	var newKeyWarn string
	var mainPage string
	if p.key == nil {
		if newKey, err := rsa.GenerateKey(rand.Reader, 4096); err == nil {
			p.key = newKey
			newKeyWarn = fmt.Sprintf("<H2>Warning! a NEW key has been created because a Private key was not uploaded</H2><iframe width='1025' height='350' sandbox='allow-same-origin allow-popups allow-forms' target='_blank' src='/view/key'; </iframe><P>\n")
		}
		mainPage = newKeyWarn
	}
	joinedPage := fmt.Sprintf("%s\n%s\n%s\n%s", web.HtmlHead, mainPage, web.HtmlFoot)
	templatePage, _ := template.New("Request").Parse(joinedPage)
	templatePage.Execute(w, p.cert.Subject)
}

func (p *PrivateData) AddHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	}

	for k, valueList := range r.PostForm {
		for _, v := range valueList {
			if len(v) > 1 {
				formRead := bytes.NewBufferString(v)
				p.addPem(PemFile(formRead))
				p.MainAction = k
				log.Printf("Added: %s", p.MainAction)
			}
		}
	}
	http.Redirect(w, r, "/view", http.StatusTemporaryRedirect)
}
