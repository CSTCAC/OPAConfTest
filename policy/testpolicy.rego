package main

import future.keywords.contains
import future.keywords.in
import future.keywords.if

## Ensure certificate presented at ingress
warn contains msg {
	input.kind=="Gateway"
	c := input.spec.servers[_]
	not c.tls.credentialName
    not c.tls.serverCertificate
	msg := sprintf("A certificate must be presented at ingress, please ensure either credentialName is present or serverCertificate and privateKey and caCertificates are present - re: `%v`", [c.port.name])
}

## Ensure certificate presented at ingress but not conflicting mounted and hcv based
warn contains msg {
	input.kind=="Gateway"
	c := input.spec.servers[_]
	c.tls.credentialName
    c.tls.serverCertificate
	msg := sprintf("Certificates must be presented as either a credentialName or serverCertificate and privateKey and caCertificates - NOT both - re: `%v`", [c.port.name])
}

## ENsure there is a certificate authorisation available for MUTUAL TLS note would not be present for Simple TLS
deny contains msg {
	input.kind=="Gateway"
	c := input.spec.servers[_]
	c.tls.mode == "MUTUAL"
	not c.tls.subjectAltNames
	not c.tls.verifyCertificateSpki
	not c.tls.verifyCertificateHash
	msg := sprintf("MUTUAL TLS must Authorise the certificate - add to port named `%v`", [c.port.name])
}

## ENsure there is a certificate authorisation available for MUTUAL TLS note would not be present for Simple TLS
warn contains msg {
	input.kind=="Gateway"
	c := input.spec.servers[_]
	not c.tls.mode == "MUTUAL"
	msg := sprintf("For internet facing patterns, MODE must be MUTUAL, for Intranet/other you must ensure client is authenticated by some means - re: `%v`", [c.port.name])
}

##Ensure TLS exists
deny contains msg {
	input.kind=="Gateway"
	c := input.spec.servers[_]
	not c.tls
	msg := sprintf("TLS must be supported on all services.  Please add a TLS field re: `%v`", [c.port.name])
}

##ensure HTTPS using common ports ---- replicate for other services
deny contains msg {
	input.kind=="Gateway"
	c := input.spec.servers[_]
	c.port.protocol == "HTTPS"
	c.port.number != 443
	c.port.number != 8443
	msg := sprintf("Please use Common Ports 443/8443 for HTTPS `%v`", [c.port.name])
}

##Ensure compliant minimum version of TLS
deny contains msg {
	input.kind=="Gateway"
	c := input.spec.servers[_]
	c.tls
	not c.tls.cipherSuites
    c.tls.minProtocolVersion=="TLSV1_2"
	msg := sprintf("Ensure that TLSV1_2 connections have cipherSuites declared re: `%v`", [c.port.name])
}

##Ensure minimum version of TLS1.2
deny contains msg {
	input.kind=="Gateway"
	c := input.spec.servers[_]
	c.tls
	not c.tls.cipherSuites
	not c.tls.minProtocolVersion=="TLSV1_2"
	not c.tls.minProtocolVersion=="TLSV1_3"
	msg := sprintf("Ensure that minimum TLSV1_2 is used and/or is declared - re: `%v`", [c.port.name])
}

##Ensure hosts are not wildcard
deny contains msg {
	input.kind=="Gateway"
           c := input.spec.servers[_].hosts[_]
           c == "*"
	msg := sprintf("Hosts cannot be wildcard re: `%v`", [c])
}

## Ensure host contains namespace as well as host ----- NEEDS SOME WORK
deny contains msg {
	input.kind=="Gateway"
	namespace_regex := "^[A-z0-9\\-\\_\\.]*\\/[A-z0-9\\-\\_\\.]*"
	c := input.spec.servers[_].hosts[_]
    not regex.match(namespace_regex, c)
	msg := sprintf("Ensure hosts fields contains namespace before hostname -`%v`", [c])
}
