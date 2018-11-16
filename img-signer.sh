#!/bin/bash

#Usage: signer.sh signer-key file-to-sign 
#	
openssl dgst -sha256 -sign $1 $2 | base64 --wrap=0  

