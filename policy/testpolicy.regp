package main

deny[msg]  {
        input.spec.servers[0].port.number != 443
        msg := "The specified port is not 443 - ensure common ports are used where required"
}

deny[msg]{
        not input.spec.tls.mode
        msg := "The deployment file does not specify a TLS mode within the TLS spec"
}

warn [msg]{
        input.spec.tls.mode != "MUTUAL"
        msg := "Check to ensure mutual authentication achieved"
}

deny[msg]  {
        not input.spec.tls.subjectAltNames
        msg := "subjectAltNmes is required withinh the TLS configuration to ensure downstream authorisation is being performed"
}
