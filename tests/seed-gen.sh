#
#  File to help generating keys to use as seeds. Theye are generated in PKCS8 format.
#  If you want the public keys they can also be extracted using openssl or other tools
#
#
function rsakey(){
local bits=$1
if ! [[ "$bits" =~ ^(2048|3072|4096)$ ]];
then
   echo "RSA keysize must be one of : 2048 3072 4096"
   return
fi


keyId=$(uuidgen | tr '[:upper:]' '[:lower:]')
echo "
Keys:
  Asymmetric:
    Rsa:
      - Metadata:
          KeyId: ${keyId}
          KeyUsage: SIGN_VERIFY # or ENCRYPT_DECRYPT
          Description: RSA key with ${bits} bits
        PrivateKeyPem: |
$(openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:${bits} -pkeyopt rsa_keygen_pubexp:65537 | sed 's/^/          /')
"
}


function ecckey(){
local curve=$1
if ! [[ "$curve" =~ ^(secp256r1|secp384r1|secp521r1)$ ]];
then
   echo "Curve must be one of: secp256r1 secp384r1 secp521r1"
   return
fi
keyId=$(uuidgen | tr '[:upper:]' '[:lower:]')

echo "
Keys:
  Asymmetric:
    Ecc:
      - Metadata:
          KeyId: ${keyId}
          KeyUsage: SIGN_VERIFY
          Description: ECC key with curve ${curve}
        PrivateKeyPem: |
$(openssl ecparam -name ${curve} -genkey -noout | sed 's/^/          /')
"
}

echo "
Source this file then run one fo the following (the output can then be pasted into a seed.yaml)
ecckey secp256r1
ecckey secp384r1
ecckey secp521r1

rsakey 2048
rsakey 3072
rsakey 4096

RSA 2048 is recommended for signing based on current Amazon pricing: https://aws.amazon.com/kms/pricing
However ECC secp256r1 creates signatures that are significantly smaller.
"
