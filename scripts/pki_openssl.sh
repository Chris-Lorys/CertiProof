#!/usr/bin/env bash
# Crée la PKI de démonstration avec la ligne de commande OpenSSL.
# Même arborescence que `python -m certiproof init` (qui l'appelle avec --openssl).
#
#   scripts/pki_openssl.sh <répertoire_données> [ID_ÉTABLISSEMENT] [NOM_ÉTABLISSEMENT]
#
# Les clés privées restent dans <répertoire_données>, exclu du dépôt Git.
set -euo pipefail

DATA="${1:?usage: $0 <répertoire_données> [id] [nom]}"
ISSUER_ID="${2:-UFS}"
ISSUER_NAME="${3:-Université Fictive du Saguenay}"
CA_DAYS=3650
ISSUER_DAYS=825

PKI="$DATA/pki"
mkdir -p "$PKI/ca" "$PKI/issuer" "$PKI/rogue" "$DATA/trust"
umask 077
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/ca.ext" <<EXT
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EXT
cat > "$TMP/issuer.ext" <<EXT
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, nonRepudiation
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
EXT

make_ca() {  # $1 = préfixe de fichier, $2 = nom de l'AC
  openssl genpkey -quiet -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$1.key.pem"
  openssl req -new -x509 -utf8 -sha384 -key "$1.key.pem" -days "$CA_DAYS" \
    -subj "/C=CA/O=$2/CN=$2" -extensions v3 -config <(printf '[req]\ndistinguished_name=dn\n[dn]\n[v3]\n'; cat "$TMP/ca.ext") \
    -out "$1.cert.pem"
}

make_issuer() {  # $1 = préfixe, $2 = rsa|ecdsa, $3 = clé AC, $4 = cert AC
  if [ "$2" = rsa ]; then
    openssl genpkey -quiet -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$1.key.pem"
  else
    openssl genpkey -quiet -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1.key.pem"
  fi
  openssl req -new -utf8 -key "$1.key.pem" \
    -subj "/C=CA/O=$ISSUER_NAME/CN=$ISSUER_NAME/serialNumber=$ISSUER_ID" -out "$TMP/req.csr"
  openssl x509 -req -sha384 -in "$TMP/req.csr" -CA "$4" -CAkey "$3" -CAcreateserial \
    -CAserial "$TMP/serial" -days "$ISSUER_DAYS" -extfile "$TMP/issuer.ext" -out "$1.cert.pem"
}

# 1. AC reconnue
make_ca "$PKI/ca/ca" "AC Démo CertiProof - Ministère fictif"
# 2. Établissement : une paire de clés par algorithme
for alg in rsa ecdsa; do
  make_issuer "$PKI/issuer/issuer-$alg" "$alg" "$PKI/ca/ca.key.pem" "$PKI/ca/ca.cert.pem"
done
# 3. Magasin de confiance du vérificateur
cp "$PKI/ca/ca.cert.pem" "$DATA/trust/ca.cert.pem"
# 4. Fausse AC et faux établissement (mêmes nom et identifiant)
make_ca "$PKI/rogue/rogue-ca" "AC Pirate"
for alg in rsa ecdsa; do
  make_issuer "$PKI/rogue/rogue-$alg" "$alg" "$PKI/rogue/rogue-ca.key.pem" "$PKI/rogue/rogue-ca.cert.pem"
done

chmod 644 "$DATA/trust/ca.cert.pem" "$PKI"/*/*.cert.pem
echo "PKI OpenSSL créée dans $PKI"
openssl x509 -in "$PKI/issuer/issuer-ecdsa.cert.pem" -noout -subject -issuer -dates
