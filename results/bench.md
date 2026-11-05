# Mesures RSA-PSS / ECDSA

Conditions : date = 2026-11-05T04:24:55Z, python = 3.13.18, platform = Linux-6.18.44-fc-v236-x86_64-with-glibc2.39, machine = x86_64, processor = x86_64, cryptography = 50.0.2, openssl = OpenSSL 4.0.3 29 Sep 2026
Répétitions : 300 signatures et vérifications par algorithme (médiane, écart-type, p95).

| Niveau | Algorithme | Signature (ms) | Vérification (ms) | Génération clé (ms) | Signature (octets) | Clé publique (octets) | Preuve (octets) |
|---|---|---|---|---|---|---|---|
| 128 bits | RSA-PSS 3072 | 1.984 ± 0.219 | 0.050 ± 0.008 | 270.92 | 384 | 422 | 2129 |
| 128 bits | ECDSA P-256 | 0.028 ± 0.006 | 0.074 ± 0.010 | 0.02 | 69–72 (moy. 71.0) | 91 | 1253 |

## Coût du hachage SHA-256 (mesuré séparément)

| Taille du PDF | Médiane (ms) | Débit (Mo/s) |
|---|---|---|
| 0.1 Mo | 0.247 | 406 |
| 1 Mo | 2.512 | 398 |
| 10 Mo | 25.308 | 395 |
