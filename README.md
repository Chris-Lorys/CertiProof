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

## Lancer l'application

Prérequis : Python 3.10 ou plus récent ([python.org](https://www.python.org/downloads/), cocher « Add Python to PATH »
sous Windows).

```bash
git clone https://github.com/Chris-Lorys/CertiProof.git
cd CertiProof
```

Puis **double-cliquez sur `lancer.bat`** (Windows) ou lancez `./lancer.sh` (macOS / Linux). Au premier lancement, le
script crée l'environnement Python et installe les dépendances. L'application s'ouvre ensuite dans le navigateur sur
http://127.0.0.1:5001.

Équivalent manuel :

```bash
python -m venv .venv
source .venv/bin/activate          # Windows : .venv\Scripts\activate
pip install -r requirements.txt
python -m certiproof               # lance l'application et ouvre le navigateur
```

Au premier lancement, un assistant demande le nom de l'établissement fictif et le mot de passe du compte
`registraire`. Il crée l'autorité de certification, les clés RSA-3072 et ECDSA P-256 de l'établissement, leurs
certificats, le magasin de confiance, une fausse AC pour les essais et le registre SQLite. Tout est écrit dans
`data/` (ou `$CERTIPROOF_DATA`), **exclu du dépôt** : clés privées (droits 0600), base, documents émis.

## Utilisation

L'application regroupe tout dans des onglets :

| Onglet | Accès | Contenu |
|---|---|---|
| Accueil | tous | État de l'installation, certificats, nombre d'attestations |
| Émission | compte de l'établissement | Émettre une attestation (RSA-PSS ou ECDSA), télécharger le PDF et la preuve, révoquer |
| Vérification | tous | Déposer un PDF et sa preuve : verdict, détail des 5 contrôles, empreintes, temps |
| Démonstration | tous (kit et panne : établissement) | Lancer les 16 scénarios, générer et télécharger le kit de fichiers falsifiés, simuler une panne du registre |
| Mesures | tous | Comparer RSA-PSS et ECDSA (temps, tailles) et le coût de SHA-256 |

Parcours de démonstration conseillé :

1. **Démonstration → Générer le kit**, puis déposer `S1b` et `S2a` dans **Vérification** : deux attestations
   identiques à l'œil, l'une acceptée, l'autre refusée pour une lettre changée.
2. Déposer `S4` (faux établissement) puis `S5` (attestation annulée).
3. **Démonstration → Simuler une panne du registre**, puis vérifier `S1b` : NON CONFIRMÉ. Remettre le registre en
   ligne : ACCEPTÉ.
4. **Démonstration → Lancer les 16 scénarios** pour le tableau complet, puis **Mesures**.

Le vérificateur interroge le registre par HTTP (`/api/registry`), comme s'il était sur une autre machine, et
n'a accès ni à la base ni aux clés.

### Ligne de commande (optionnelle)

Les mêmes fonctions restent disponibles sans interface :

```bash
python -m certiproof init --password "..."        # installation sans l'assistant (--openssl : PKI via la CLI OpenSSL)
python -m certiproof issue --type diplome --holder "Alice Tremblay" \
    --program "Baccalauréat en informatique" --grade "Excellent" --date 2026-06-15 --alg rsa
python -m certiproof verify data/issued/UFS-2026-XXXX.pdf data/issued/UFS-2026-XXXX.proof.json
python -m certiproof revoke UFS-2026-XXXX --reason "Erreur de saisie"
python -m certiproof serve --port 8080 --no-browser
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
  web.py        application Flask (accueil, émission, vérification, démonstration, mesures)
  scenarios.py  jeu d'essai et rapport attendu / observé
  bench.py      mesures RSA-PSS / ECDSA et SHA-256
scripts/pki_openssl.sh   création de la PKI avec la CLI OpenSSL
lancer.bat / lancer.sh   lancement en un clic (installe les dépendances au premier lancement)
tests/                   tests pytest
results/                 rapports des essais et des mesures
```

Séparation des droits : seul le compte de l'établissement (session, mot de passe haché, jetons CSRF) peut émettre,
révoquer, générer le kit ou simuler une panne. L'espace Vérification n'utilise que le magasin de confiance et l'API
publique en lecture seule du registre.
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
