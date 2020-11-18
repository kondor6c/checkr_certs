Goals
=====

* An all in one binary to work with certificates (hence the current "heredoc" like variables in var-data.go)
* Copies existing certificates, allowing for individuals to "just copy what's existing"
* Pull the certificate from a remote location
* check public keys of the certificates, hopefully checking for re-use of private keys.

The goals have changed since I first worte this, it began simply as the ability to just copy a certificate to a CSR. This functionality exists in newer versions of openssl, but I wanted it sooner and Go's x509 module looked very nice and easy. I then wanted to track public key re-use, and figured I could expand this to finding "test" keys used from a default install or perhaps a compromised key. It just began to keep expanding and be fun; and likely will continue to do so.

The web interface should be very simple to use and not expose many complexities of x509 certificates. But it should also be strict and not allow for misconfigurations or other mistakes. And the fact that heredoc variables was directly a desired use case. The reasoning was that I didn't want to ship around files that also had to be in a specific directory. I wanted to hand this binary to a manager or customer and they could run it, point their web browser and handle certificates themselves. 
Much of this was going to use a CLI, but then I took a deep look at cfssl (and lost some motivation around the time that I did look at the project). But I think I've continued to a point where there might be some cool things that I can bring to the table. Therefore I plan on discontinuing the cli portion and going forward with the API and database side.
