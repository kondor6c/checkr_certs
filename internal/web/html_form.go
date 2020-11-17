package web

import "html/template"

// TODO: add form to JSON convert, send that to API (migration path to BOTH embedded forms AND a central JSON Schema openAPIv3!
const (
	ICalExpire string = `
BEGIN:VCALENDAR
VERSION:2.0
CALSCALE:GREGORIAN
BEGIN:VEVENT
SUMMARY: [FATAL] x509 certificate expiration
DTSTART=20130802T103400
DTENDTZID=20130802T110400
LOCATION: Common Name is 
DESCRIPTION: SAN is 
STATUS:CONFIRMED
SEQUENCE:3
BEGIN:VALARM
TRIGGER:-PT7D
DESCRIPTION:[WARN] x509 certificate expiration
ACTION:DISPLAY
END:VALARM
END:VEVENT
END:VCALENDAR
`
	HtmlHead template.HTML = `<HTML>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<!-- Goal: embedded simple no JS form based site, editing this might be hard/ugly, sorry -->
  <meta charset="utf-8">
  <HEAD><TITLE>Certificate Utility WebUI</TITLE></HEAD>
  <BODY>
	<BR>
	<STYLE>
      table, th, td {
      border: 1px solid black;
   	  }
   	</STYLE>
	<P>[<A HREF="/options">Configure Options</A>]</P>
	<P>[<A HREF="/">Main (back)</A>]</P>
`
	HtmlFoot template.HTML = `
	<P>
	Only RSA keys are supported currently
	To obtain the modulus from openssl remember to not include the newline character or any other fields. All characters should be upper case.
	Go now ignores the Common Name if is a SAN is found.
	When remotely connecting, you can use a SOCKS proxy by setting the environment variable HTTP_PROXY="socks5://127.0.0.1:5544"
	</BODY></HTML>`

	EditView template.HTML = `
	<BR>
    <form action="/edit" method="post" autocomplete="on">
      <label for="CSR"><h5>Common Name:</h5></label>
    <textarea name="Common Name" id="edit-csr" rows="2" cols="20" placeholder={{.CommonName}}></textarea></div>
	  <br>
      <label for="add"><h5>Locality:</h5></label>
    <textarea name="Locality" id="edit-csr" rows="2" cols="20">{{.Locality}}</textarea></div>
	  <br>
      <label for="add"><h5>Province:</h5></label>
    <textarea name="Locality" id="edit-csr" rows="2" cols="20">{{.Locality}}</textarea></div>
	  <br>
      <label for="add"><h5>Country:</h5></label>
    <textarea name="Organization" id="edit-csr" rows="2" cols="20">{{.Organization}}</textarea></div>
	  <br>
      <label for="add"><h5>Organization:</h5></label>
    <textarea name="Organization" id="edit-csr" rows="2" cols="20">{{.Organization}}</textarea></div>
	  <br>
      <label for="add"><h5>Organizational Unit:</h5></label>
    <textarea name="OrganizationalUnit" id="edit-csr" rows="2" cols="20">{{.OrganizationalUnit}}</textarea></div>
	  <br>
      <label for="add"><h5>Street Address:</h5></label>
    <textarea name="StreetAddress" id="edit-csr" rows="2" cols="20">{{.StreetAddress}}</textarea></div>
	  <br>
      <label for="add"><h5>Postal Code:</h5></label>
    <textarea name="Postal Code" id="edit-csr" rows="2" cols="20">{{.PostalCode}}</textarea></div>
	  <br>
      <label for="add"><h5>Extra Names:</h5></label>
    <textarea name="Subject Alt Names" id="edit-csr" rows="2" cols="20">{{.ExtraNames}}</textarea></div>
	  <br>
      <div>
        <div class="button">
        <button type="submit">Generate CSR{{.}}</button>
      </div>
	  </form>
	      <BR>
    <form action="/csr" method="post" autocomplete="off">
    <label for="CSR"><h5>CSR:</h5></label>
    <textarea name="CSR" id="csr-content" rows="30" cols="80">{{.CSR}}</textarea></div>
	</form>
    <br>
	<iframe width="1025" height="350" sandbox="allow-same-origin allow-popups allow-forms" target="_blank" src="/view/key"; </iframe>
    <br>
`
	CertView template.HTML = `
		<P>[<A HREF="/edit">edit</A>]</P>
    	<TABLE style="width:100%" >
    	<TR><TD>CN [click to edit]</TD><TD>Locality</TD><TD>Organization</TD><TD>Organiztional Unit</TD><TD>Email</TD><TD>Issuer</TD><TD>Subject Alt Names</TD><TD>Expire [click for calendar event]</TD><TD>Public Key MD5 hash</TD></TR>
`
	KeyView template.HTML = `
 	<TABLE style="width:100%" >
 	<TR><TD>ID</TD><TD>Bit Length Size</TD><TD>Public Modulus (SHA-1)</TD><TD>Public Modulus (MD5)</TD></TR>
`
	MainPage template.HTML = `
	<BR>
    <form action="/add" method="post" autocomplete="off">
    {{ range .ActionChoices }}
      <label for="add"><h5>{{.}}:</h5></label>
      <textarea name="{{.}}" id="add-{{.}}" rows="10" cols="80"></textarea></div>
	  <br>
	{{ end }}
      <div>
        <div class="button">
        <button type="submit">Submit {{.}}</button>
      </div>
	  </form>

	  <h4>OR (Not Working, currently planned) </h4>
	  <form method="post" enctype="multipart/form-data">
    {{ range .ActionChoices }}
       <div>
         <label for="file">Choose file to upload (not working yet!) </label>
         <input type="file" id="file-{{.}}" accept=".pem,.crt, text/plain, application/x-java-jce-keystore, application/x-java-keystore, application/x-x509-ca-cert, application/x-pem-file, application/x-pkcs12" >
       </div>
    {{ end }}
       <div>
         <button>Submit</button>
       </div>
      </form>
    </form>
    <form action="/fetch" method="get" autocomplete="off">
     <div>
      <label for="fetch"><h5>Remote Address:</h5></label>
      <textarea name="rAddress" id="Remote Address" rows="1" cols="80"></textarea></div>
     </div>
    <br>
      <label for="fetch"><h5>Remote Port:</h5></label>
      <textarea name="rPort" id="Remote Port" rows="1" cols="10"></textarea></div>
     </div>
     <div class="button">
       <button type="submit">Submit Remote Fetch</button>
     </div>
   </form>
`
)
