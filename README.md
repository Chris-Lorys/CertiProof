# CertiProof

Vérification de diplômes et d'attestations par signatures numériques.
Projet du cours 8INF874 Cryptographie (UQAC, automne 2026). Équipe : Daren HOUEDANOU et Fredy Loïc NGUE TCHANA.

L'établissement signe une attestation une seule fois. Le destinataire (recruteur, université) dépose ensuite le PDF et
son fichier de preuve dans le vérificateur, qui répond à trois questions distinctes :

| Question | Contrôle | Notion du cours |
|---|---|---|
| Qui a signé ? | Le certificat de l'émetteur est émis par une AC reconnue à l'avance, et la signature de la preuve est valide | PKI, signatures (séance 10), RSA (6–7), courbes elliptiques (11) |
| Le document a-t-il changé ? | Le SHA-256 du PDF reçu est égal à l'empreinte signée | Hachage SHA (séance 12) |
| Est-il encore valide ? | Le registre de l'établissement renvoie une réponse **signée** et liée à un nonce : `valid`, `revoked` ou `unknown` | Signatures, protection contre le rejeu |

> Toutes les données sont fictives. L'établissement « Université Fictive du Saguenay » et son AC sont générés localement.

## Installation

Prérequis : Python 3.10 ou plus récent. OpenSSL n'est nécessaire que pour l'option `--openssl`.

```bash
git clone https://github.com/Chris-Lorys/CertiProof.git
cd CertiProof
python -m venv .venv
source .venv/bin/activate          # Windows : .venv\Scripts\activate
pip install -r requirements.txt

# Crée l'AC, les clés RSA-3072 et ECDSA P-256 de l'établissement, le magasin de confiance,
# une fausse AC pour les essais, le registre SQLite et le compte de l'établissement.
python -m certiproof init --password "choisir-un-mot-de-passe"
# variante : la même PKI créée avec la ligne de commande OpenSSL
python -m certiproof init --openssl --force --password "..."
```

Tout est écrit dans `data/` (ou `$CERTIPROOF_DATA`), **exclu du dépôt** : clés privées (droits 0600), base, documents émis.

## Utilisation

### Interface web locale

Deux applications séparées, pour séparer les droits :

```bash
python -m certiproof serve-issuer     # http://127.0.0.1:5001  émission + révocation (connexion obligatoire)
python -m certiproof serve-verifier   # http://127.0.0.1:5002  vérification seulement
```

1. Sur `:5001`, se connecter avec le compte `registraire`, remplir le formulaire et choisir RSA-PSS ou ECDSA.
2. Télécharger le PDF et sa preuve (`.proof.json`) depuis le registre.
3. Sur `:5002`, déposer les deux fichiers. Le verdict et chaque contrôle sont affichés.
4. Révoquer l'attestation sur `:5001`, puis vérifier de nouveau : signature correcte, mais document annulé.
5. Arrêter `serve-issuer`, puis vérifier : résultat **NON CONFIRMÉ** (registre inaccessible), les contrôles
   cryptographiques restant affichés. Relancer le serveur : le statut est de nouveau confirmé.

### Ligne de commande

```bash
python -m certiproof issue --type diplome --holder "Alice Tremblay" \
    --program "Baccalauréat en informatique" --grade "Excellent" --date 2026-06-15 --alg rsa
python -m certiproof verify data/issued/UFS-2026-XXXX.pdf data/issued/UFS-2026-XXXX.proof.json
python -m certiproof revoke UFS-2026-XXXX --reason "Erreur de saisie"
python -m certiproof verify --offline doc.pdf doc.proof.json   # sans interroger le registre
```

### Essais de falsification et mesures (lot 3)

```bash
python -m certiproof scenarios     # results/scenarios.md + results/fichiers/ (jeu d'essai complet)
python -m certiproof bench         # results/bench.md, bench.csv, bench.json
python -m certiproof bench --all-levels   # ajoute le niveau 192 bits (RSA-7680 / P-384, plus lent)
python -m pytest                   # tests automatisés
```

`scenarios` crée une PKI jetable dans `data/scenarios/` à chaque exécution, sans toucher au registre réel.
Les résultats déjà présents dans `results/` ont été produits sur une machine Linux x86_64 ; **relancez-les sur votre
machine** pour le rapport, puisque les temps en dépendent.

## Résultats attendus

| # | Situation | Verdict |
|---|---|---|
| S1 | PDF original + preuve correcte (RSA-PSS et ECDSA) | ACCEPTÉ |
| S2 | Nom, note ou date modifiés, ou un seul bit du PDF | REFUSÉ, fichier différent |
| S3 | Signature altérée, preuve d'un autre PDF, empreinte remplacée dans la preuve | REFUSÉ, signature incorrecte ou fichier différent |
| S4 | Faux établissement (même nom et identifiant, AC non reconnue) | REFUSÉ, émetteur inconnu |
| S5 | Attestation annulée | REFUSÉ, document révoqué (signature correcte) |
| S6 | Registre inaccessible, puis de retour | NON CONFIRMÉ, puis ACCEPTÉ |
| S7 | Preuve absente | REFUSÉ, preuve absente |
| S8 | Réponse du registre forgée ou rejouée | NON CONFIRMÉ, réponse non authentique |

## Format de la preuve

```json
{
  "format": "certiproof-proof/1",
  "record": {
    "doc_id": "UFS-2026-3F9A1C7B",
    "issuer_id": "UFS",
    "hash_alg": "SHA-256",
    "pdf_sha256": "4a5587…7270",
    "issued_at": "2026-11-05T04:30:00Z",
    "registry_url": "http://127.0.0.1:5001/api/registry"
  },
  "signature": { "alg": "ECDSA-SHA256", "value": "<base64>" },
  "certificate": "-----BEGIN CERTIFICATE----- …"
}
```

Octets signés : `"CertiProof/record/v1\0" || JSON canonique(record)` (clés triées, sans espaces, UTF-8).
Les réponses du registre sont signées avec le préfixe `"CertiProof/status/v1\0"`, ce qui empêche de réutiliser une
signature d'un contexte dans l'autre.

Paramètres : RSA-PSS 3072 bits, MGF1-SHA-256, sel de 32 octets ; ECDSA P-256 / SHA-256 (environ 128 bits de sécurité
pour les deux, NIST SP 800-57). Le vérificateur refuse un algorithme qui ne correspond pas à la clé du certificat,
ainsi que les clés RSA de moins de 3072 bits et les courbes autres que P-256, P-384 et P-521.

## Architecture

```
certiproof/
  signing.py    RSA-PSS / ECDSA (bibliothèque cryptography, adossée à OpenSSL)
  pki.py        AC, certificats d'établissement, magasin de confiance, validation des certificats
  proof.py      format de la preuve, JSON canonique, SHA-256
  pdfgen.py     génération des attestations PDF (reportlab, sortie reproductible)
  registry.py   registre SQLite : statuts et comptes (mots de passe hachés)
  issuer.py     service d'émission, révocation, réponses de statut signées
  verifier.py   vérification complète et verdict
  web.py        applications Flask d'émission et de vérification
  scenarios.py  jeu d'essai et rapport attendu / observé
  bench.py      mesures RSA-PSS / ECDSA et SHA-256
scripts/pki_openssl.sh   création de la PKI avec la CLI OpenSSL
tests/                   tests pytest
results/                 rapports des essais et des mesures
```

Séparation des droits : seul le compte de l'établissement (session, mot de passe haché, jetons CSRF) peut émettre
ou révoquer. Le vérificateur n'a accès qu'au magasin de confiance et à l'API publique en lecture seule du registre.
Il n'interroge le registre qu'**après** avoir validé le certificat et la signature, pour ne jamais contacter une
adresse fournie par un tiers non reconnu.

## Limites

- CertiProof ne garantit ni la véracité des informations saisies par l'établissement ni l'identité de la personne qui
  présente le document.
- Toute modification des octets du PDF, même bénigne (réenregistrement, métadonnées), invalide l'empreinte.
- La sécurité dépend de la protection de la clé privée de l'émetteur. Dans le prototype, elle est stockée en clair
  dans `data/` avec des droits restreints ; en production, on utiliserait un HSM ou au moins une clé chiffrée.
- La révocation d'une **attestation** est implémentée. La révocation d'un **certificat** (CRL/OCSP), la gestion d'une
  clé compromise, le renouvellement des certificats et la conservation des preuves sur plusieurs années (horodatage
  de confiance) sont traités dans le rapport, pas dans le prototype.
- Le registre est servi en HTTP local. Ses réponses étant signées et liées à un nonce, un intermédiaire ne peut pas
  les falsifier ni les rejouer, mais il peut les bloquer, ce qui donne le verdict NON CONFIRMÉ.
