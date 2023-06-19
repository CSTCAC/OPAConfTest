package main

import future.keywords.contains
import future.keywords.in

##---------------------------------------------------- FC1 - Ensure TLS ----------------------------------------------------
##All servers must support TLS
deny contains msg {
	c := input.spec.servers[_]
	not c.tls
	msg := sprintf("FC1 - TLS must be supported on all services.  Please add a TLS field to the port named `%v`", [c.port.name])
}

##---------------------------------------------------- FC2 - Common Ports ----------------------------------------------------
##ensure HTTPS using common ports ---- replicate for other services
deny contains msg {
	c := input.spec.servers[_]
	c.port.protocol == "HTTPS"
	c.port.number != 443
	c.port.number != 8443
	msg := sprintf("FC2 - HTTPS - For HTTPS please use Common Ports `%v`", [c.port.name])
}

##---------------------------------------------------- FC3 - Declare Cipher Suites ----------------------------------------------------
##Ensure CipherSuites declared - ARRAY Format
deny contains msg {
	c := input.spec.servers[_]
	c.tls
	not c.tls.cipherSuites
	msg := sprintf("FC3 - Ensure that TLS connections have cipherSuites are delared for port `%v`", [c.port.name])
}

##---------------------------------------------------- FC4 - Declare Cert Authorisation ----------------------------------------------------
## ENsure there is a certificate authorisation available for MUTUAL TLS
deny contains msg {
	c := input.spec.servers[_]
	c.tls.mode == "MUTUAL"
	not c.tls.subjectAltNames
	not c.tls.verifyCertificateSpki
	not c.tls.verifyCertificateHash
	msg := sprintf("FC4 - MUTUAL TLS must Authorise the certificate - add to port named `%v`", [c.port.name])
}

##---------------------------------------------------- FC5 - Declare Namespace with host ----------------------------------------------------
## Ensure host contains namespace
deny contains msg {
	namespace_regex := "^[A-z0-9\\-\\_\\.]*\\/[A-z0-9\\-\\_\\.]*"
	c := input.spec.servers[_].hosts[_]
    not regex.match(namespace_regex, c)
msg := sprintf("FC5 - Ensure hosts fields contains namespace before hostname -`%v`", [c])
}

##---------------------------------------------------- FC5A - Hosts cannot be wildcard ----------------------------------------------------
deny contains msg {
	c := input.spec.servers[_].hosts[_]
    c == "*"
	msg := sprintf("FC5A - Hosts cannot be wildcard `%v`", [c.port.name])
}
