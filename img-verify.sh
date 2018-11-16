#!/bin/bash

#Usage: verifier.sh signer-cert file signature  

pubk=$(mktemp)
sigf=$(mktemp)

openssl x509 -in $1 -pubkey -noout > $pubk 

echo $3 | base64 -d --wrap=0 > $sigf 

openssl dgst -sha256 -verify $pubk -signature $sigf $2

rm -rf $pubk $sigf

