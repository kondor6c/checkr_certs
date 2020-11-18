package pki

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
)

//POST, PEM cert, respond with cert details
func (p *PrivateData) RespondJSONHandler(w http.ResponseWriter, r *http.Request) {
	if err := json.NewDecoder(r.Body).Decode(p.config); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if len(p.config.PEM) >= 10 {
		ioRead := bytes.NewBufferString(p.config.PEM)
		p.addPem(PemFile(ioRead))
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(createOutput(p.cert))
	defer r.Body.Close()
}

func (p *PrivateData) RemoteURLHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	var inquiry JsonInquiry
	defer r.Body.Close()
	if DebugSet == true {
		buf := new(bytes.Buffer)
		buf.ReadFrom(r.Body)
		log.Printf("here's what we got:")
		log.Println(buf.String())
	}

	if err := json.NewDecoder(r.Body).Decode(&inquiry); err != nil {
		log.Println("error at json, TODO correctly handle this! ")
		WebCatcher(w, err)
		return
	}
	strPort := strconv.Itoa(inquiry.Port)
	log.Printf("host %v   port %v", inquiry.Hostname, strPort)

	rCert := fetchRemoteCert(inquiry.Protocol, inquiry.Hostname, strPort)
	//verifiedRemoteChain := getChain(rCert)
	p.cert = *rCert[0] //dereference
	jsonOutput := createOutput(p.cert)
	log.Printf("%v", string(jsonOutput))
	w.Write(jsonOutput)
	if len(rCert) > 1 {
		go recordIssuer(rCert) // This would be nice to make concurrent!!
	}
	recordRemoteCert(p.cert, inquiry)
	//Catcher(err, 10008, "error from our custom written function to fetch remote certificates")

	log.Printf("Fetched remote %s and returned JSON \n", inquiry.Hostname)

}
func (p *PrivateData) RemoteCertIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	log.Printf("we got: %v", r.Body)
	qCert := &FullCert{} //a query for a certificate
	if err := json.NewDecoder(r.Body).Decode(&qCert); err != nil {
		log.Println("error at json, TODO correctly handle this! ")
		WebCatcher(w, err)
		return
	}
	certResults := certLookup(*qCert)
	resultingJson := createOutput(certResults)

	w.Write(resultingJson)
	defer r.Body.Close()

}

// https://github.com/goharbor/harbor/blob/b664b90b8641859acae96a21ca912781f74753ff/src/jobservice/api/handler.go#L286
// GET
func (p *PrivateData) PrivateKeyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Write(createOutput(p.cert))
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(p.config); err != nil {
		// https://github.com/goharbor/harbor/blob/b664b90b8641859acae96a21ca912781f74753ff/src/jobservice/api/handler.go#L286
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// GET
func (p *PrivateData) X509CertHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Write(createOutput(p.cert))
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(p.config); err != nil {
		// https://github.com/goharbor/harbor/blob/b664b90b8641859acae96a21ca912781f74753ff/src/jobservice/api/handler.go#L286
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

/* pulled from Agola (CI)
https://github.com/agola-io/agola/blob/master/internal/services/runservice/api/api.go#L83
*/

// easy, better is the http
func WebCatcher(w http.ResponseWriter, err error) {
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("error"))
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Println(err)
	}
}
