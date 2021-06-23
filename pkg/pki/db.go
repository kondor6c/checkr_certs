package pki

import (
	"crypto/x509"
	"log"
	"os"
	"strings"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
)

// terminology: Signatures belongs to keys, and they are applied to the thing (certs) that keys act on, fingerprints belong to the key, this is a change, to much of the code and terminology
var db *sqlx.DB

func DBInit() { //seriously need to look at this again, what a mess trying to get multiple SQL queries in one variable, the queries are valid but it doesn't like executing them
	dbUser := os.Getenv("DBUSER")
	dbPass := os.Getenv("DBPASS")
	dbHost := os.Getenv("DBHOST")
	dbPort := os.Getenv("DBPORT")
	dbName := os.Getenv("DBNAME")
	dbOpts := os.Getenv("DBOPTS")
	var dberr error
	var table_meta = `CREATE TABLE IF NOT EXISTS meta_info (
		id MEDIUMINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
		host_name TEXT,
		alternate TEXT,
		links TEXT,
		port_number INT,
		protocol TEXT,
		added TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		source_agent TEXT NOT NULL,
		tags TEXT,
		trust_parent TEXT,
		no_record bool DEFAULT FALSE);`
	var table_key = `CREATE TABLE IF NOT EXISTS public_keys (
		id BIGINT AUTO_INCREMENT PRIMARY KEY,
		public_fp TEXT,
		strength_size TEXT,
		pem BLOB REFERENCES pem_store (pem_block),
		key_usage TEXT,
		fp_hash_type TEXT,
		algorithm TEXT,
		added timestamp DEFAULT CURRENT_TIMESTAMP,
		meta_tx MEDIUMINT REFERENCES meta_info (id) );`

	var table_pem_store = `CREATE TABLE IF NOT EXISTS pem_store (
		signature VARCHAR(20) PRIMARY KEY,
		pem_block BLOB,
		pem_type VARCHAR(60),
		added timestamp DEFAULT CURRENT_TIMESTAMP,
		meta_tx MEDIUMINT REFERENCES meta_info (id) );`
	var table_staple = `CREATE TABLE IF NOT EXISTS stapled (
		id BIGINT AUTO_INCREMENT PRIMARY KEY,
		url TEXT,
		linked_cert TEXT REFERENCES pub_certs (signature),
		sig TEXT,
		checked_status TEXT,
		added DATETIME DEFAULT NOW(),
		meta_tx BIGINT REFERENCES meta_info (id) );`
	var table_issuer = `CREATE TABLE IF NOT EXISTS issuer 
		( signature VARCHAR(128) PRIMARY KEY,
		signature_alg TEXT,
		common_name TEXT,
		serial_number TEXT,
		key_fp TEXT REFERENCES public_keys (public_fp), 
		country TEXT,
		organization TEXT,
		organizational_unit TEXT,
		locality TEXT,
		province TEXT,
		street_address TEXT,
		postal_code TEXT,
		partial bool,
		meta_tx BIGINT REFERENCES meta_info (id) );`
	var table_pub_cert = `CREATE TABLE IF NOT EXISTS public_certificate ( common_name TEXT,
		serial_number TEXT, 
		key_fp TEXT REFERENCES public_keys (public_fp), 
		country VARCHAR(64), 
		organization TEXT,
		organizational_unit TEXT, 
		locality TEXT,
		province TEXT, 
		street_address TEXT,
		postal_code TEXT, 
		not_before DATETIME,
		not_after DATETIME,
		signature VARCHAR(128) PRIMARY KEY,
		signature_algorithm TEXT,
		keyUsage TEXT,
		alt_names TEXT,
		subject_key_id VARCHAR(128),
		authority_key_id TEXT,
		non_standard TEXT,
		meta_tx MEDIUMINT REFERENCES meta_info (id) ); `
	if len(dbOpts) < 1 {
		dbOpts = "parseTime=true&interpolateParams=true&charset=utf8mb4"
	}
	if len(dbHost) < 1 {
		dbOpts = "127.0.0.1"
	}
	if len(dbPort) < 1 {
		dbOpts = "3306"
	}
	if len(dbName) < 1 {
		dbName = "multicheck"
	}
	if len(dbPass) < 1 || len(dbUser) < 1 || len(dbHost) < 1 {
		log.Printf("I don't know how to connect to the database! Please set DBPASS DBUSER and DBHOST")
	} else {
		db, dberr = sqlx.Connect("mysql", dbUser+":"+dbPass+"@tcp("+dbHost+":"+dbPort+")/multicheck"+"?"+dbOpts)
		log.Printf("hit %v", string("database table insert"))
		Catcher(dberr, 10003, "failed to connect to the database")
	}
	_, aerr := db.Exec(table_meta)
	Catcher(aerr, 100004, "Failed to insert metadata table")
	_, berr := db.Exec(table_key)
	Catcher(berr, 100005, "Failed to insert private key table")
	_, cerr := db.Exec(table_issuer)
	Catcher(cerr, 100006, "Failed to insert issuer table")
	_, derr := db.Exec(table_pem_store)
	Catcher(derr, 100007, "Failed to insert pem storage table")
	_, eerr := db.Exec(table_pub_cert)
	Catcher(eerr, 100008, "Failed to insert public certificate table")
	_, ferr := db.Exec(table_staple)
	Catcher(ferr, 100009, "Failed to insert stapled cert table")

}

func certLookup(query FullCert) []FullCert {
	// I wanted to accept an x509.Certificate and log it, but I would need to re-convert (thus do more work) many fields like the sha1
	var lerr error
	var look *sqlx.Rows
	var qPublicCertBASE string = `SELECT common_name,
		serial_number,
		key_fp,
		country,
		organization,
		organizational_unit,
		locality,
		province,
		street_address,
		postal_code,
		not_before,
		not_after,
		signature,
		signature_algorithm,
		keyUsage,
		alt_names,
		subject_key_id,
		authority_key_id,
		nonstandard FROM pub_certs`
	var qPublicCertSig string = qPublicCertBASE + " WHERE signature = ?"
	var qPublicCertDate string = qPublicCertBASE + " WHERE not_after >= ? AND not_after <= ?"
	var qPublicCertKey string = qPublicCertBASE + " WHERE key_fp = ?"
	var qPublicCertAltName string = qPublicCertBASE + " WHERE sans REGEXP '^(?)'"
	var qPublicCertAuthorityKey string = qPublicCertBASE + "WHERE signature LIKE ?"
	var qPublicCertCN string = qPublicCertBASE + ` WHERE (common_name,
		serial_number,
		key_fp,
		country,
		organization,
		organizational_unit,
		locality,
		province,
		street_address,
		postal_code) ILIKE ?`
	var qPublicCertCAName string = qPublicCertBASE + ` WHERE (common_name,
		serial_number,
		key_fp,
		country,
		organization,
		organizational_unit,
		locality,
		province,
		street_address,
		postal_code) ILIKE ?`
	var certResults = []FullCert{}
	if len(query.Signature) > 0 {
		look, lerr = db.Queryx(qPublicCertSig, query.Signature)

	} else if query.NotAfter.IsZero() && query.NotBefore.IsZero() {
		look, lerr = db.Queryx(qPublicCertDate, query.NotAfter, query.NotBefore)

	} else if len(query.Key.PublicFP) > 0 {
		look, lerr = db.Queryx(qPublicCertKey, query.Key.PublicFP)

	} else if len(query.Subject.CommonName) > 0 {
		look, lerr = db.Queryx(qPublicCertCN, query.Subject)
	} else if len(query.Issuer.Name.CommonName) > 0 {
		look, lerr = db.Queryx(qPublicCertCAName, query.Issuer)

	} else if len(query.Extensions.Sans) > 0 {
		look, lerr = db.Queryx(qPublicCertAltName, strings.Join(query.Extensions.Sans, "|"))

	} else if len(query.Extensions.AKI) > 0 {
		look, lerr = db.Queryx(qPublicCertAuthorityKey, query.Extensions.AKI)
	} else {
		log.Printf("No search criteria")
	}

	Catcher(lerr, 100012, "could not query the database")
	for look.Next() {
		c := &FullCert{}
		look.StructScan(c)
		certResults = append(certResults, *c)
	}

	return certResults
}

var insertIssuer = `INSERT INTO issuer (common_name,
			serial_number,
			country,
			organization,
			organizational_unit,
			locality, province,
			street_address,
			postal_code,
			key_fp,
			partial,
			meta_tx) VALUES(:common_name,
			:serial_number,
			:country,
			:organization,
			:organizational_unit,
			:locality,
			:province,
			:street_address,
			:postal_code,
			:fingerprint,
			:partial,
			:metaID)`

func recordRemoteCert(fCert x509.Certificate, request JsonInquiry) {
	// I wanted to accept an x509.Certificate and log it, but I would need to re-convert (thus do more work) many fields like the sha1
	ins := db.MustBegin()
	var insert_meta = "INSERT INTO meta_info (host_name, port_number, protocol, source_agent, tags, trust_parent, no_record) VALUES (?,?,?,?,?,?,?);"
	var insert_key = "INSERT INTO public_keys (public_fp, strength, pem, key_usage, fp_hash_type, algorithm,  meta_tx ) VALUES (?,?,?,?,?,?,?);"
	var count int
	//var insert_cert = "INSERT INTO pub_certs (host_name, common_name, serial_number, key_fp, country, organization, organizational_unit, locality, province, street_address, postal_code, not_before, not_after, signature, signature_algorithm, keyUsage, sans, subject_key_id, authority_key_id, nonstandard,meta_tx) VALUES(?,?,?,(SELECT public_fp FROM keys WHERE public_fp = ?),?,?,?,?,?,?,?,?, ?,?,?,?,?,?,?,?,?)"
	metaResult, err := db.Exec(insert_meta, request.Hostname, request.Port, request.Protocol, "api-user", "", "", 0)
	Catcher(err, 10005, "internal error when trying to record the certificate, this should be ignored by the end user")
	pubCert := parseCert(fCert)
	db.QueryRowx("SELECT COUNT(*) FROM public_certificate WHERE signature = ?", pubCert.Signature).Scan(&count)
	if metaID, err := metaResult.LastInsertId(); metaID >= 1 && err == nil && count <= 0 {
		var issuerCount int
		type insertCert struct {
			tempCert FullCert `db:""`
			metaTX   int64    `db:"metaID"`
			parentCA string   `db:"p_aki"`
			issuer   LiteCert `db:""`
		}
		if len(pubCert.Extensions.AKI) > 1 {
			// record the issuer, basing of the authority key identifier remember issuers use LiteCert
			db.QueryRowx("SELECT COUNT(*) FROM issuer WHERE public_fp = ?", pubCert.Extensions.AKI).Scan(&issuerCount)
			if issuerCount >= 1 {
				_, err := ins.NamedExec(insertIssuer, insertCert{issuer: LiteCert{Name: pubCert.Issuer.Name}, parentCA: pubCert.Extensions.AKI, metaTX: metaID})
				Catcher(err, 10806, "internal error when trying to record the certificate, this should be ignored by the end user")
			}
		}
		ins.Exec(insert_key, pubCert.Key.PublicFP, pubCert.Key.Strength, pubCert.Key.PEM, pubCert.Key.KeyRole, pubCert.Key.FPdigest, pubCert.Key.Algorithm, metaID)

		//ins.Exec("SELECT meta_tx FROM public_keys WHERE public_fp = :public_fp", pubCert.Key.FPdigest)
		var insertPublic = `INSERT INTO public_certificate (common_name,
			serial_number,
			country,
			organization,
			organizational_unit,
			locality,
			province,
			street_address,
			postal_code,
			not_before,
			not_after,
			signature,
			signature_algorithm,
			keyUsage,
			alt_names,
			subject_key_id,
			authority_key_id,
			non_standard) VALUES(:common_name,
			:serial_number,
			:country,
			:organization,
			:organizational_unit,
			:locality,
			:province,
			:street_address,
			:postal_code,
			:not_before,
			:not_after,
			:signature,
			:signature_algorithm,
			:key_role,
			:alt_names,
			:subject_key_id,
			:authority_key_id,
			:non_standard_data)`
		_, err := ins.NamedExec(insertPublic, pubCert)
		Catcher(err, 10807, "internal error when trying to record the certificate, this should be ignored by the end user")
		dberr := ins.Commit()
		if dberr != nil {
			Catcher(dberr, 10808, "internal error when trying to insert the Public certificate, this should be ignored by the end user")
			ins.Rollback()
		}
	} else {
		log.Printf("failed to record meta transaction information, database connection potentially down. count: %d, meta: %d, err: %s", count, metaID, err)
	}
}

func recordIssuer(caSent []*x509.Certificate) {
	var caCount int
	for i, _ := range caSent {
		caCert := parseCert(*caSent[i])
		db.QueryRowx("SELECT COUNT(*) FROM issuer WHERE signature = ?", caCert.Signature).Scan(&caCount)
		if caSent[i].IsCA && caCount <= 0 {
			var issuerCount int
			if len(caCert.Extensions.AKI) > 1 {
				db.QueryRowx("SELECT COUNT(*) FROM issuer WHERE key_fp = ?", caCert.Extensions.AKI).Scan(&issuerCount) // WHERE key_fp
				if issuerCount >= 1 {
					_, err := db.NamedExec(insertIssuer, caCert)
					Catcher(err, 10809, "internal error when trying to record the CA, this should be ignored by the end user")
				}
			}
		}
	}
}
