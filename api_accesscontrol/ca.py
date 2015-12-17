#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Andy Sayler
# Copyright 2015

### Imports ###

import time
import uuid

from OpenSSL import crypto




def generate_cert(req_csr_txt, ca_key_txt, ca_crt_txt):

    ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, ca_key_txt)
    ca_crt = crypto.load_certificate(crypto.FILETYPE_PEM, ca_crt_txt)
    req_csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, req_csr_txt)

    req_crt = crypto.X509()
    req_crt.gmtime_adj_notBefore(0)
    req_crt.gmtime_adj_notAfter(60*60*24*365)
    req_crt.set_serial_number(1)
    req_crt.set_issuer(ca_crt.get_subject())
    req_crt.set_pubkey(req_csr.get_pubkey())
    subj = req_csr.get_subject()
    subj.commonName = str(uuid.uuid4())
    req_crt.set_subject(subj)
    req_crt.sign(ca_key, 'sha256')

    return crypto.dump_certificate(crypto.FILETYPE_PEM, req_crt).decode()

if __name__ == "__main__":

    with open('./devcert-test.csr', 'r') as f:
        req_csr_txt = f.read()
    with open('./ca-inter-test.key', 'r') as f:
        ca_key_txt = f.read()
    with open('./ca-inter-test.crt', 'r') as f:
        ca_crt_txt = f.read()

    print(req_csr_txt)

    req_crt_txt = generate_cert(req_csr_txt, ca_key_txt, ca_crt_txt)

    print(req_crt_txt)
