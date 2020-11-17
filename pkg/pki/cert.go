package pki

// TODO! defer, flags with default values, router/decider of actions and keypairs. Functions should have interfaces
// Pemfile is probably the best example of interfaces
import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"

	_ "github.com/go-sql-driver/mysql"
)

var DebugSet = false

// Catcher : Generic Catch all, better than just discarding errors
func Catcher(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

// getPublicKeyDigest: returns RSA public key modulus MD5 hash. TODO: support other key types
func getPublicKeyDigest(pkey rsa.PublicKey) string {
	hexString := fmt.Sprintf("%X", pkey.N)
	md5sum := sha1.New()
	md5sum.Write([]byte(hexString))
	digest := fmt.Sprintf("%x\n", sha1.Sum(nil))
	return digest
}

// fetchRemoteCert: try to remotely pull a certificate. This would be useful for private or secure environments where you want to copy what is existing and make a new CSR
func fetchRemoteCert(proto string, cHost string, cPort string) ([]*x509.Certificate, error) { //TODO offer SOCKS and remote resolution (dialer), since Golang already supports HTTP_PROXY?
	config := tls.Config{InsecureSkipVerify: true}
	conn, err := tls.Dial(proto, cHost+":"+cPort, &config)
	var rerr error
	//var sentCertificate []x509.Certificate
	if err != nil {
		log.Println(err)
		rerr = errors.New("An error occurred while trying to remotely fetch the certificate")
	}
	defer conn.Close()
	log.Println("client: connected to: ", conn.RemoteAddr())
	state := conn.ConnectionState()
	// reflect.ValueOf(state).Interface().(newType)
	return state.PeerCertificates, rerr
}

func (p *PrivateData) addPem(dataPem *pem.Block) {
	if dataPem.Type == "RSA PRIVATE KEY" || dataPem.Type == "PRIVATE KEY" {
		key, err := x509.ParsePKCS1PrivateKey(dataPem.Bytes)
		if err != nil {
			pkcs8, err := x509.ParsePKCS8PrivateKey(dataPem.Bytes)
			Catcher(err)
			p.key = pkcs8.(*crypto.PrivateKey) // hmm
		} else {
			p.key = key
		}
	} else if dataPem.Type == "EC PRIVATE KEY" {
		if key, err := x509.ParseECPrivateKey(dataPem.Bytes); err == nil {
			p.key = key
		}
	} else if dataPem.Type == "CERTIFICATE" {
		pemCert, err := x509.ParseCertificate(dataPem.Bytes)
		Catcher(err)
		p.cert = *pemCert
	} else {
		log.Println("unsupported ") //TODO return error
		log.Fatal(dataPem.Type)
	}
}

// toPem: take a crypto like thing and create a PEM object from it
func toPem(crypt interface{}) []byte {
	// for ref: https://stackoverflow.com/questions/20065304/differences-between-begin-rsa-private-key-and-begin-private-key
	pemBytes := new(bytes.Buffer)
	var byteData []byte
	var pemType string
	var err error

	if DebugSet == true {
		log.Printf("converting to pem:  %T\n", crypt)
	}

	switch t := crypt.(type) {
	case x509.Certificate:
		if t.Signature != nil {
			byteData = t.Raw
			pemType = "CERTIFICATE"
		}
	case rsa.PrivateKey:
		byteData = x509.MarshalPKCS1PrivateKey(&t)
		pemType = "RSA PRIVATE KEY"
	case rsa.PublicKey:
		byteData, err = asn1.Marshal(t)
		//Should NOT be hit, because the cert should only have valid data, I don't know how it couldn't be valid
		Catcher(err)
		pemType = "RSA PUBLIC KEY"
	case x509.CertificateRequest:
		if t.Signature != nil {
			byteData = t.Raw
			pemType = "CERTIFICATE REQUEST"
		}
	case certAuthority:
		for _, authority := range t.ca {
			byteData = append(byteData, authority.Raw...)
			pemType = "CERTIFICATE"
		}
	}
	err = pem.Encode(pemBytes, &pem.Block{Type: pemType, Bytes: byteData})
	Catcher(err)

	return pemBytes.Bytes()
}

// I don't remember why I had two pkeys, I think the independent function is newer and better
func (p *PrivateData) pkey() crypto.Signer {
	switch c := p.key.(type) {
	case *rsa.PrivateKey:
		return interface{}(c).(crypto.Signer)
	case *ecdsa.PrivateKey:
		return interface{}(c).(crypto.Signer)
	/*	case ed25519.PrivateKey:
		priv := pk.(ed25519.PrivateKey)
	*/
	default:
		return nil
	}
}

// pkey: from a private key, get something that we can use to create a new certificate or work with
func pkey(pk crypto.PrivateKey) crypto.Signer {
	switch c := pk.(type) {
	case rsa.PrivateKey:
		return interface{}(c).(crypto.Signer)
	case ecdsa.PrivateKey:
		return interface{}(c).(crypto.Signer)
		/*	case ed25519.PrivateKey:
			priv := pk.(ed25519.PrivateKey)
		*/
	default:
		return nil
	}
}

func (p *PrivateData) certCreation(requestCert []byte) *x509.Certificate { // TODO use "crypto.Signer", since it can be used with a HSM (and FIPS 140-2 level 2)
	var cert []byte
	var err error
	var signer crypto.Signer
	devRand, oerr := os.Open("/dev/random")
	defer devRand.Close()
	Catcher(oerr)
	//if the authority's key is not present then create a self signed
	signer = p.key.(crypto.Signer)
	template := &x509.Certificate{
		Subject:            p.req.Subject,
		PublicKeyAlgorithm: p.req.PublicKeyAlgorithm,
		PublicKey:          p.req.PublicKey,
		SignatureAlgorithm: SignerAlgo(signer.Public(), p.config.Hash), // question: does the key signing capabilities matter for the signing key or key to be issued? I think the current signing key
	}
	if p.auth.key != nil {
		signer = p.key.(crypto.Signer)
		cert, err = x509.CreateCertificate(devRand, template, template, signer.Public(), signer)
	} else if len(p.auth.ca) >= 1 {
		signer = p.auth.key.(crypto.Signer)
		cert, err = x509.CreateCertificate(devRand, template, &p.auth.ca[0], signer.Public(), signer)
	}
	Catcher(err)
	checkcert, err := x509.ParseCertificate(cert)
	Catcher(err)
	return checkcert
}

// copyCert: copies an existing x509 cert as a new CSR
func copyCert(source x509.Certificate) x509.CertificateRequest {
	var destCert x509.CertificateRequest
	destCert.DNSNames = source.DNSNames
	destCert.Subject = source.Subject
	destCert.SignatureAlgorithm = source.SignatureAlgorithm
	destCert.EmailAddresses = source.EmailAddresses
	destCert.IPAddresses = source.IPAddresses
	return destCert
}

func (p *PrivateData) keyPairReq(csr requestCert) []byte {
	p.req = x509.CertificateRequest{
		Subject: *csr.Names.convertPKIX(),
	}

	devRand, oerr := os.Open("/dev/random")
	Catcher(oerr)
	defer devRand.Close()
	req, genCsrErr := x509.CreateCertificateRequest(devRand, &p.req, p.key)
	Catcher(genCsrErr)
	_, err := x509.ParseCertificateRequest(req) //extra check, just to see if the CSR is correct
	Catcher(err)
	return req
}

// SignerAlgo: take public key determine permissible algorithms, attempt user selected algorithm, can be blank
func SignerAlgo(pub crypto.PublicKey, tryAlg string) x509.SignatureAlgorithm {
	var rHash x509.SignatureAlgorithm
	switch c := pub.(type) {
	case rsa.PublicKey:
		bitLength := interface{}(c).(rsa.PublicKey).N.BitLen()
		if bitLength >= 4096 || tryAlg == "SHA512" || tryAlg == "SHA5" {
			rHash = x509.SHA512WithRSA
		} else if bitLength >= 3072 || tryAlg == "SHA384" || tryAlg == "SHA3" {
			rHash = x509.SHA384WithRSA
		} else if bitLength >= 2048 || tryAlg == "SHA384" || tryAlg == "SHA3" {
			rHash = x509.SHA256WithRSA
		} else if tryAlg == "SHA" || tryAlg == "SHA1" {
			rHash = x509.SHA1WithRSA
		}
	case ecdsa.PublicKey:
		curve := interface{}(c).(ecdsa.PublicKey).Curve
		if curve == elliptic.P521() || tryAlg == "SHA512" || tryAlg == "SHA5" {
			rHash = x509.ECDSAWithSHA512
		} else if curve == elliptic.P384() || tryAlg == "SHA384" || tryAlg == "SHA3" {
			rHash = x509.ECDSAWithSHA384
		} else if curve == elliptic.P256() || tryAlg == "SHA256" || tryAlg == "SHA2" {
			rHash = x509.ECDSAWithSHA256
		} else if tryAlg == "SHA" || tryAlg == "SHA1" {
			rHash = x509.ECDSAWithSHA1
		}
	default:
		rHash = x509.UnknownSignatureAlgorithm
	}
	return rHash
}

// SignatureString: sourced from cfssl, translate known signature type to string
func SignatureString(alg x509.SignatureAlgorithm) string {
	switch alg {
	case x509.MD2WithRSA:
		return "MD2WithRSA"
	case x509.MD5WithRSA:
		return "MD5WithRSA"
	case x509.SHA1WithRSA:
		return "SHA1WithRSA"
	case x509.SHA256WithRSA:
		return "SHA256WithRSA"
	case x509.SHA384WithRSA:
		return "SHA384WithRSA"
	case x509.SHA512WithRSA:
		return "SHA512WithRSA"
	case x509.DSAWithSHA1:
		return "DSAWithSHA1"
	case x509.DSAWithSHA256:
		return "DSAWithSHA256"
	case x509.ECDSAWithSHA1:
		return "ECDSAWithSHA1"
	case x509.ECDSAWithSHA256:
		return "ECDSAWithSHA256"
	case x509.ECDSAWithSHA384:
		return "ECDSAWithSHA384"
	case x509.ECDSAWithSHA512:
		return "ECDSAWithSHA512"
	default:
		return "Unknown Signature"
	}
}

/*
func gatherOpts() configStore {
	/* option ideas: output format (ie json, text, template),
	   check inputs (check key belongs to cert if both passed otherwise just check cert, or check rsa pubkey),
	   env read from env vars,
	   AIO cert, ca chain, and key are all in one file/env
	opt := &configStore{}
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
	if DebugSet == true {
		log.Printf("obtained arguments: %s", os.Args)
	}
	if flag.NFlag() < 1 && os.Stdin == nil {
		flag.PrintDefaults()
	}
	return *opt
}
func main() {
	var optCertIn string
	opts := gatherOpts()
	dat := decideRoute(opts)
	dbinit()
	if opts.ActionSecondary == "debug" {
		DebugSet = true
	}
	if opts.ActionPrimary == "web-ui" || opts.ActionPrimary == "web-server" {
		mux := http.NewServeMux()
		mux.HandleFunc("/", dat.mainHandler)
		mux.HandleFunc("/add", dat.addHandler)
		mux.HandleFunc("/view", dat.viewHandler)
		mux.HandleFunc("/view/ical", dat.icalHandler)
		mux.HandleFunc("/view/cert", dat.servePemHandler)
		mux.HandleFunc("/view/csr", dat.servePemHandler)
		mux.HandleFunc("/view/key", dat.servePemHandler)
		mux.HandleFunc("/api", dat.respondJSONHandler)
		mux.HandleFunc("/api/cert", dat.x509CertHandler)
		mux.HandleFunc("/api/cert/remote", dat.remoteURLHandler)
		mux.HandleFunc("/api/key", dat.privateKeyHandler)
		mux.HandleFunc("/edit", dat.editHandler)
		mux.HandleFunc("/fetch", dat.fetchHandler)
		http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
		log.Fatal(http.ListenAndServe(":5000", mux))
	}
	fmt.Println(optCertIn)
	parseCert(dat.cert)
}
*/

func (c *CertName) convertPKIX() *pkix.Name {
	rName := &pkix.Name{
		Country:            []string{c.Country},
		Organization:       []string{c.Organization},
		OrganizationalUnit: []string{c.OrganizationalUnit},
		Locality:           []string{c.Locality},
		Province:           []string{c.Province},
		StreetAddress:      []string{c.StreetAddress},
		PostalCode:         []string{c.PostalCode},
		CommonName:         c.CommonName,
	}
	return rName
}

// parseName: from a certificate pull any kind of field in the name section
func parseName(n pkix.Name) CertName {
	name := CertName{
		CommonName:         n.CommonName,
		SerialNumber:       n.SerialNumber,
		Country:            strings.Join(n.Country, ","),
		Organization:       strings.Join(n.Organization, ","),
		OrganizationalUnit: strings.Join(n.OrganizationalUnit, ","),
		Locality:           strings.Join(n.Locality, ","),
		Province:           strings.Join(n.Province, ","),
		StreetAddress:      strings.Join(n.StreetAddress, ","),
		PostalCode:         strings.Join(n.PostalCode, ","),
	}
	return name
}

// parseExtentsions: pulls x509 extensions from a certificate
func parseExtensions(c x509.Certificate) Extensions {
	sans := c.EmailAddresses
	for _, ip := range c.IPAddresses {
		sans = append(sans, ip.String())
	}
	//RFC 5280 4.2.1.1 issuer name and serial number OR SKI of issuer
	//policyASN := asn1.ObjectIdentifier{2, 5, 29, 32} //RFC 5280 4.2.1.2 For end entity certificates, subject key identifiers SHOULD be derived from the public key. And Should be 160 bit SHA1 (4.2.1.2 rfc2459)
	//var policyString string
	//asn1.Unmarshal(policyASN, &policyString)

	/*policy := string(pkix.Extension{
		Id: policyASN,
	}.Value) */
	log.Printf("extension policy: \n")
	sans = append(sans, c.DNSNames...)
	e := Extensions{
		Sans:     sans,
		AltNames: strings.Join(sans, ","),
		KeyUsage: []string{"c.ExtKeyUsage"},
		AKI:      hex.EncodeToString(c.AuthorityKeyId),
		SKI:      hex.EncodeToString(c.SubjectKeyId),
	}
	return e
}

// Parse the key portion of the config "Key"
func (p *PrivateData) configKey(jk jKey) {
	if len(jk.PEM) <= 1 {
		devRand, oerr := os.Open("/dev/random")
		Catcher(oerr)
		defer devRand.Close()
		if newKey, err := rsa.GenerateKey(rand.Reader, 4096); err == nil {
			Catcher(err)
			p.key = newKey
		}
	}
}

// resultingKey: takes in any type switch crypto.key{} and parse it
func resultingKey(pk interface{}) jKey { //TODO support multiple key types like ed25519 and more, should I parse the actual PEM key now and potentially call key creation?
	rKey := jKey{}
	if DebugSet == true {
		log.Printf("%T\n", pk)
	}
	switch k := pk.(type) {
	case *rsa.PrivateKey:
		rKey.KeyRole = "PrivateKey"
		rKey.PublicFP = fmt.Sprintf("%v", sha1.Sum(k.PublicKey.N.Bytes()))
		rKey.FPdigest = "sha1"
		rKey.Algorithm = "rsa"
	case *rsa.PublicKey:
		rKey.Algorithm = "rsa"
		h := sha1.New()
		h.Write(k.N.Bytes())
		hash := h.Sum(nil)
		rKey.PEM = string(toPem(*k))
		rKey.Strength = strconv.Itoa(k.N.BitLen())
		rKey.PublicFP = hex.EncodeToString(hash)
	case *ecdsa.PublicKey:
		rKey.KeyRole = "PublicKey"
		rKey.Algorithm = "ecdsa"
	case *ecdsa.PrivateKey:
		rKey.KeyRole = "PrivateKey"
		rKey.Algorithm = "ecdsa"
	case ecdsa.PublicKey:
		rKey.Algorithm = "ecdsa"
		h := sha1.New()
		h.Write(k.X.Bytes())
		rKey.Strength = k.Params().Name
		hash := h.Sum(nil)
		rKey.PublicFP = hex.EncodeToString(hash)
	}
	return rKey
}

// parseCert: takes an x509 cert and gives an custom annotated data type so that it can be recorded or acted on
func parseCert(c x509.Certificate) fullCert {
	keyVal := resultingKey(c.PublicKey)
	h := sha1.New()
	h.Write(c.Signature)
	hash := h.Sum(nil)
	sig := SignatureString(c.SignatureAlgorithm)
	if DebugSet == true {
		log.Printf("cert's key is: %v", keyVal)
	}
	rCert := fullCert{
		Subject:            parseName(c.Subject), // pkix.Name, country, org, ou, l, p, street, zip, serial, cn, extra... Additional elements in a DN can be added in via ExtraName, <=EMAIL
		Issuer:             LiteCert{Name: parseName(c.Issuer)},
		NotAfter:           c.NotAfter,
		NotBefore:          c.NotBefore,
		Key:                keyVal,
		SignatureAlgorithm: sig,
		Signature:          hex.EncodeToString(hash),
		Extensions:         parseExtensions(c),
	}
	return rCert
}

// createOutput: converts data our interface types to json, that is annotated in var-data
func createOutput(crypt ...interface{}) []byte {
	var jsonOut []byte
	var err error
	cryptObject := &fullOutput{}
	cryptObject.Certs = make([]fullCert, 0)

	for _, i := range crypt {
		switch t := i.(type) {
		case x509.Certificate:
			//if j, err := json.Marshal(parseCert(t)); err == nil {
			//	log.Println(j)
			cryptObject.Certs = append(cryptObject.Certs, parseCert(t))
			//}
		case rsa.PrivateKey:
			//if j, err := json.Marshal(resultingKey(t)); err == nil {
			cryptObject.Keys = append(cryptObject.Keys, resultingKey(t))
			//}
		}
	}
	jsonOut, err = json.Marshal(cryptObject)
	Catcher(err)
	return jsonOut
}

// pemFile : a core function, takes a file returns the decoded PEM
func PemFile(file io.Reader) *pem.Block {
	bytesAll, _ := ioutil.ReadAll(file)
	pemContent, rest := pem.Decode(bytesAll)
	if rest != nil && pemContent == nil {
		log.Println("no _valid_ pem data was passed. Please check")
	}
	return pemContent
}

// getChain: try to obtain the chain if it has been given to us or is in the system Trust store
func getChain(certs []x509.Certificate) [][]*x509.Certificate {
	intermediatePool := x509.NewCertPool()
	rootPool := x509.NewCertPool()
	var certificate x509.Certificate
	compareCert := x509.VerifyOptions{Intermediates: intermediatePool, Roots: rootPool}
	// This feels rather brute force, I can revisit this later with hard calculations of signatures and public keys from each
	for _, c := range certs {
		if c.IsCA == true {
			intermediatePool.AddCert(&c)
			rootPool.AddCert(&c)
		} else if c.KeyUsage == x509.KeyUsageDigitalSignature {
			certificate = c
		}
	}
	verifiedBundle, err := certificate.Verify(compareCert)
	if err != nil {
		log.Println(err)
		sysRoot, err := x509.SystemCertPool()
		Catcher(err)
		failedChain, err := certificate.Verify(x509.VerifyOptions{Roots: sysRoot})
		verifiedBundle = failedChain
		Catcher(err)
	}
	return verifiedBundle
}
