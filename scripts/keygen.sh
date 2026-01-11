#!/usr/bin/env bash
set -euo pipefail

# Emits ONE YAML key entry (a single "- KeyId: ...") suitable to paste under "Keys:".
# Usage:
#   ./keygen.sh SYMMETRIC_DEFAULT
#   ./keygen.sh RSA_2048
#   ./keygen.sh ECC_NIST_P256
#   ./keygen.sh HMAC_256
#   ./keygen.sh ML_DSA_65

die() { echo "error: $*" >&2; exit 1; }

need() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

need openssl
need uuidgen
need sed
need tr

indent_pem() { sed 's/^/        /'; }  # 8 spaces for PEM lines under Material: PrivateKeyPem: |

new_key_id() { uuidgen | tr '[:upper:]' '[:lower:]'; }

# Produce N random bytes as uppercase hex (no 0x prefix).
rand_hex() {
  local bytes="$1"
  openssl rand -hex "${bytes}" | tr '[:lower:]' '[:upper:]'
}

# Check whether OpenSSL supports a particular public key algorithm name.
# (Works across many OpenSSL builds/providers.)
openssl_supports_pkey_alg() {
  local alg="$1"
  openssl genpkey -algorithm "${alg}" -out /dev/null >/dev/null 2>&1
}

emit_symmetric_default() {
  local keyId desc
  keyId="$(new_key_id)"
  desc="AES Key"

  # SYMMETRIC_DEFAULT is 256-bit in KMS
  local k1 k2
  k1="$(rand_hex 32)"

  cat <<YAML
  - KeyId: ${keyId}
    Metadata:
      KeySpec: SYMMETRIC_DEFAULT
      Description: ${desc}
    Material:
      BackingKeys:
        - ${k1}
YAML
}

emit_hmac() {
  local keyspec="$1" bytes desc keyId
  keyId="$(new_key_id)"
  desc="HMAC key ${keyspec}"

  case "${keyspec}" in
    HMAC_224) bytes=28 ;;
    HMAC_256) bytes=32 ;;
    HMAC_384) bytes=48 ;;
    HMAC_512) bytes=64 ;;
    *) die "unsupported HMAC KeySpec: ${keyspec}" ;;
  esac

  local k1 k2
  k1="$(rand_hex "${bytes}")"

  cat <<YAML
  - KeyId: ${keyId}
    Metadata:
      KeySpec: ${keyspec}
      KeyUsage: GENERATE_VERIFY_MAC
      Description: ${desc}
    Material:
      BackingKeys:
        - ${k1}
YAML
}

emit_rsa() {
  local keyspec="$1" bits desc keyId
  keyId="$(new_key_id)"

  case "${keyspec}" in
    RSA_2048) bits=2048 ;;
    RSA_3072) bits=3072 ;;
    RSA_4096) bits=4096 ;;
    *) die "unsupported RSA KeySpec: ${keyspec}" ;;
  esac

  desc="RSA key with ${bits} bits"

  cat <<YAML
  - KeyId: ${keyId}
    Metadata:
      KeySpec: ${keyspec}
      KeyUsage: SIGN_VERIFY
      Description: ${desc}
    Material:
      PrivateKeyPem: |
$(openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:${bits} -pkeyopt rsa_keygen_pubexp:65537 | indent_pem)
YAML
}

emit_ecc_nist() {
  local keyspec="$1" curve desc keyId
  keyId="$(new_key_id)"

  case "${keyspec}" in
    ECC_NIST_P256) curve="secp256r1" ;;
    ECC_NIST_P384) curve="secp384r1" ;;
    ECC_NIST_P521) curve="secp521r1" ;;
    *) die "unsupported ECC NIST KeySpec: ${keyspec}" ;;
  esac

  desc="ECC key with curve ${curve}"

  cat <<YAML
  - KeyId: ${keyId}
    Metadata:
      KeySpec: ${keyspec}
      KeyUsage: SIGN_VERIFY
      Description: ${desc}
    Material:
      PrivateKeyPem: |
$(openssl ecparam -name "${curve}" -genkey -noout | indent_pem)
YAML
}

emit_ecc_secg_k1() {
  local keyId curve desc
  keyId="$(new_key_id)"
  curve="secp256k1"
  desc="ECC key with curve ${curve}"

  cat <<YAML
  - KeyId: ${keyId}
    Metadata:
      KeySpec: ECC_SECG_P256K1
      KeyUsage: SIGN_VERIFY
      Description: ${desc}
    Material:
      PrivateKeyPem: |
$(openssl ecparam -name "${curve}" -genkey -noout | indent_pem)
YAML
}

emit_ed25519() {
  local keyId desc
  keyId="$(new_key_id)"
  desc="ECC key with Ed25519"

  cat <<YAML
  - KeyId: ${keyId}
    Metadata:
      KeySpec: ECC_NIST_EDWARDS25519
      KeyUsage: SIGN_VERIFY
      Description: ${desc}
    Material:
      PrivateKeyPem: |
$(openssl genpkey -algorithm Ed25519 | indent_pem)
YAML
}

emit_mldsa() {
  local keyspec="$1" alg desc keyId
  keyId="$(new_key_id)"

  case "${keyspec}" in
    ML_DSA_44) alg="ML-DSA-44" ;;
    ML_DSA_65) alg="ML-DSA-65" ;;
    ML_DSA_87) alg="ML-DSA-87" ;;
    *) die "unsupported ML-DSA KeySpec: ${keyspec}" ;;
  esac

  # Ensure OpenSSL supports ML-DSA keygen.
  if ! openssl_supports_pkey_alg "${alg}"; then
    die "your OpenSSL does not support ${alg} (try OpenSSL 3.5+ with the default/FIPS provider enabled)"
  fi

  desc="ML-DSA key ${keyspec}"

  cat <<YAML
  - KeyId: ${keyId}
    Metadata:
      KeySpec: ${keyspec}
      KeyUsage: SIGN_VERIFY
      Description: ${desc}
    Material:
      PrivateKeyPem: |
$(openssl genpkey -algorithm "${alg}" | indent_pem)
YAML
}

usage() {
  cat >&2 <<'EOF'
Usage: gen-kms-seed-snippet.sh <KeySpec>

KeySpec values supported:
  SYMMETRIC_DEFAULT
  RSA_2048 | RSA_3072 | RSA_4096
  ECC_NIST_P256 | ECC_NIST_P384 | ECC_NIST_P521
  ECC_SECG_P256K1
  ECC_NIST_EDWARDS25519
  HMAC_224 | HMAC_256 | HMAC_384 | HMAC_512
  ML_DSA_44 | ML_DSA_65 | ML_DSA_87

Example:
  ./keygen.sh ECC_NIST_P256
EOF
  exit 2
}

main() {
  [[ $# -eq 1 ]] || usage
  local keyspec="$1"

  case "${keyspec}" in
    SYMMETRIC_DEFAULT) emit_symmetric_default ;;
    RSA_2048|RSA_3072|RSA_4096) emit_rsa "${keyspec}" ;;
    ECC_NIST_P256|ECC_NIST_P384|ECC_NIST_P521) emit_ecc_nist "${keyspec}" ;;
    ECC_SECG_P256K1) emit_ecc_secg_k1 ;;
    ECC_NIST_EDWARDS25519) emit_ed25519 ;;
    HMAC_224|HMAC_256|HMAC_384|HMAC_512) emit_hmac "${keyspec}" ;;
    ML_DSA_44|ML_DSA_65|ML_DSA_87) emit_mldsa "${keyspec}" ;;
    SM2) emit_sm2 ;;
    *) die "unknown/unsupported KeySpec: ${keyspec}" ;;
  esac
}

main "$@"
