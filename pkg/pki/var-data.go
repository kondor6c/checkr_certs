package pki

import (
	"crypto"
	"crypto/x509"
	"time"
)

// This is "secret" data, therefore named private
type PrivateData struct { //TODO make this an interface!
	key        crypto.PrivateKey
	cert       x509.Certificate
	req        x509.CertificateRequest
	auth       certAuthority
	trust      x509.CertPool
	MainAction string
	mode       string
	config     requestCert

	options ConfigStore
}
type JsonInquiry struct {
	Service  string `json:"service,omitempty"  db:"service"`
	Type     string `json:"type,omitempty"  db:"type"`
	Category string `json:"category,omitempty"  db:"category"`
	Port     int    `json:"port,omitempty"  db:"port"`
	Tls      bool   `json:"tls,omitempty"  db:"tls"`
	Ipv6     bool   `json:"ipv6,omitempty"  db:"ipv6"`
	Protocol string `json:"protocol,omitempty"  db:"protocol"`
	Hostname string `json:"hostname,omitempty"  db:"hostname"`
}
type remoteURI struct {
	Host     string `json:"host" db:"remote_host"`
	Port     int    `json:"port" db:"remote_port"`
	Protocol string `json:"protocol" db:"remote_protocol"`
}

type NamedError struct {
	Result    interface{}
	Code      int // exit code place for looking up what happened and where. This is critical to presenting the type of errors, did the server timeout, was the cert not trusted?
	PlaceText string
	Force     bool // try to force continue
	Err       error
}

var DebugSet = false
var ForceError = false

type privKey interface {
	regularKey() crypto.PrivateKey
}

type certAuthority struct {
	ca  []x509.Certificate
	key crypto.PrivateKey
}

type user struct {
	ID       int      `json:"id,omitempty"  db:"id"`
	Username *string  `json:"username,omitempty"  db:"username"`
	Name     *string  `json:"name,omitempty"  db:"name"`
	Email    *string  `json:"email,omitempty"  db:"email"`
	Groups   []string `json:"groups,omitempty" db:"groups"`
	Password *string  `json:"password,omitempty"  db:"password"`
}
type CertName struct {
	CommonName         string `json:"common_name,omitempty" db:"common_name"`
	SerialNumber       string `json:"serial_number,omitempty" db:"serial_number"`
	Country            string `json:"country,omitempty" db:"country"`
	Organization       string `json:"organization,omitempty" db:"organization"`
	OrganizationalUnit string `json:"organizational_unit,omitempty" db:"organizational_unit"`
	Locality           string `json:"locality,omitempty" db:"locality"`
	Province           string `json:"province,omitempty" db:"province"`
	StreetAddress      string `json:"street_address,omitempty" db:"street_address"`
	PostalCode         string `json:"postal_code,omitempty" db:"postal_code"`
	Business           string //2.5.4.15
	Email              string //1.2.840.113549.1.9.1
	//Names              []interface{} `json:"names,omitempty"`
}

type jKey struct {
	PEM       string `json:"pem" db:"pem"`
	KeyRole   string `json:"key_role" db:"key_role"`
	Strength  string `json:"strength" db:"strength"`
	PublicFP  string `json:"public_signature_fingerprint" db:"public_fp"`
	FPdigest  string `json:"fingerprint_digest_type" db:"fp_hash_type"`
	Algorithm string `json:"algorithm" db:"algorithm"`
}

// a certificate authority "identity", one that has been previously detected/known like GoDaddy issuing 1, or internal company CA #5. Primary key should be sigSha1
// This is mostly to help identify certificates, since names are like gpg uid's, the key ID/signature really matters therefore tracking the sig sha1
type authID struct {
	Name    string
	Id      string
	SigHash []byte
}

type LiteCert struct {
	Name          CertName `json:"issuing_name,omitempty" db:""`
	Fingerprint   string   `json:"fingerprint" db:"fingerprint"`
	SignatureHash string   `json:"fp_hash" db:"fp_hash"`
	metaLink      authID   `json:"link_to_identity,omitempty" db:"db_id"`
}

type FullOutput struct {
	Certs     []FullCert  `json:"certs"`
	Keys      []jKey      `json:"keys"`
	CertAuths []LiteCert  `json:"authorities"`
	Meta      interface{} `json:"meta_info"`
}

type FullCert struct {
	Subject            CertName   `json:"subject,omitempty" db:""`
	Issuer             LiteCert   `json:"issuer" db:"issuer"`
	SerialNumber       string     `json:"serial_number,omitempty" db:"serial_number"`
	NotBefore          time.Time  `json:"not_before" db:"not_before"`
	NotAfter           time.Time  `json:"not_after" db:"not_after"`
	SignatureAlgorithm string     `json:"sigalg" db:"signature_algorithm"`
	Signature          string     `json:"signature_hash" db:"signature"`
	PEM                string     `json:"pem" db:"pem"`
	Key                jKey       `json:"key" db:""`
	Extensions         Extensions `json:"extensions,omitempty" db:""`
}

type Extensions struct {
	AKI       string         `json:"authority_key_id,omitempty" db:"authority_key_id"`
	SKI       string         `json:"subject_key_id,omitempty" db:"subject_key_id"`
	AltNames  string         `json:"alt_names_string,omitempty" db:"alt_names"`
	Sans      []string       `json:"sans,omitempty" db:"sans"`
	KeyUsage  []string       `json:"key_capabilities,omitempty" db:"key_usage"`
	ExtraData nonStandardExt `json:"payload,omitempty" db:""`
}

type nonStandardExt struct {
	NonStandardData string `json:"non_standard_data" db:"non_standard_data"`
	encoding        string `json:"encoding"`
	data            []byte
}

type ConfigStore struct {
	List            string //
	CertIn          string
	CaIn            string
	KeyIn           string
	CertOut         string
	CaOut           string
	KeyOut          string
	ActionPrimary   string
	ActionSecondary string
	ActionChoices   []string
}

type requestCert struct {
	Role     string      `json:"role"`
	PEM      string      `json:"pem",omitempty`
	Duration string      `json:"duration,omitempty"`
	Encoding string      `json:"encoding,omitempty"`
	Hash     string      `json:"hash"`
	CN       string      `json:"CN,omitempty"`
	Hosts    []string    `json:"hosts"`
	Names    CertName    `json:"names,omitempty"`
	Key      jKey        `json:"key,omitempty"`
	Payload  interface{} `json:"payload,omitempty"`
	Issuer   interface{} `json:"issuing_link,omitempty"`
}
