# Essais de falsification CertiProof

Conditions : date = 2026-11-05T20:49:26Z, python = 3.13.18, platform = Linux-6.18.44-fc-v242-x86_64-with-glibc2.39, machine = x86_64, processor = x86_64, cryptography = 50.0.2, openssl = OpenSSL 4.0.3 29 Sep 2026

| # | Scénario | Attendu | Observé | Preuve | Émetteur reconnu | Signature | Intégrité du PDF | Statut (registre) | Conforme |
|---|---|---|---|---|---|---|---|---|---|
| S1a | PDF signé original (RSA-PSS) | ACCEPTÉ (OK) | ACCEPTÉ (OK) | ✔ | ✔ | ✔ | ✔ | ✔ | oui |
| S1b | PDF signé original (ECDSA) | ACCEPTÉ (OK) | ACCEPTÉ (OK) | ✔ | ✔ | ✔ | ✔ | ✔ | oui |
| S1c | PDF d'origine + preuve fournie à part (compatibilité) | ACCEPTÉ (OK) | ACCEPTÉ (OK) | ✔ | ✔ | ✔ | ✔ | ✔ | oui |
| S2a | Nom modifié dans le PDF | REFUSÉ (FICHIER_DIFFERENT) | REFUSÉ (FICHIER_DIFFERENT) | ✔ | ✔ | ✔ | ✘ | ✔ | oui |
| S2b | Note modifiée dans le PDF | REFUSÉ (FICHIER_DIFFERENT) | REFUSÉ (FICHIER_DIFFERENT) | ✔ | ✔ | ✔ | ✘ | ✔ | oui |
| S2c | Date modifiée dans le PDF | REFUSÉ (FICHIER_DIFFERENT) | REFUSÉ (FICHIER_DIFFERENT) | ✔ | ✔ | ✔ | ✘ | ✔ | oui |
| S2d | Un seul bit modifié dans la partie signée | REFUSÉ (FICHIER_DIFFERENT) | REFUSÉ (FICHIER_DIFFERENT) | ✔ | ✔ | ✔ | ✘ | ✔ | oui |
| S2e | Note remplacée par une mise à jour ajoutée après la signature | REFUSÉ (CONTENU_AJOUTE_APRES_SIGNATURE) | REFUSÉ (CONTENU_AJOUTE_APRES_SIGNATURE) | ✔ | ✔ | ✔ | ✘ | ✔ | oui |
| S3a | Signature altérée (1 bit) | REFUSÉ (SIGNATURE_INCORRECTE) | REFUSÉ (SIGNATURE_INCORRECTE) | ✔ | ✔ | ✘ | ✔ | – | oui |
| S3b | Preuve d'un autre document jointe au PDF | REFUSÉ (FICHIER_DIFFERENT) | REFUSÉ (FICHIER_DIFFERENT) | ✔ | ✔ | ✔ | ✘ | ✔ | oui |
| S3c | Empreinte de la preuve remplacée par celle du faux PDF | REFUSÉ (SIGNATURE_INCORRECTE) | REFUSÉ (SIGNATURE_INCORRECTE) | ✔ | ✔ | ✘ | ✔ | – | oui |
| S4 | Document signé par un émetteur inconnu (fausse AC) | REFUSÉ (EMETTEUR_INCONNU) | REFUSÉ (EMETTEUR_INCONNU) | ✔ | ✘ | ✔ | ✔ | – | oui |
| S5 | Attestation annulée | REFUSÉ (DOCUMENT_REVOQUE) | REFUSÉ (DOCUMENT_REVOQUE) | ✔ | ✔ | ✔ | ✔ | ✘ | oui |
| S6a | Registre inaccessible | NON CONFIRMÉ (REGISTRE_INACCESSIBLE) | NON CONFIRMÉ (REGISTRE_INACCESSIBLE) | ✔ | ✔ | ✔ | ✔ | – | oui |
| S6b | Retour du registre | ACCEPTÉ (OK) | ACCEPTÉ (OK) | ✔ | ✔ | ✔ | ✔ | ✔ | oui |
| S7 | PDF sans preuve CertiProof | REFUSÉ (PREUVE_ABSENTE) | REFUSÉ (PREUVE_ABSENTE) | ✘ | – | – | – | – | oui |
| S8a | Réponse du registre forgée (document révoqué déclaré valide) | NON CONFIRMÉ (REPONSE_REGISTRE_INVALIDE) | NON CONFIRMÉ (REPONSE_REGISTRE_INVALIDE) | ✔ | ✔ | ✔ | ✔ | – | oui |
| S8b | Réponse du registre rejouée (mauvais nonce) | NON CONFIRMÉ (REPONSE_REGISTRE_INVALIDE) | NON CONFIRMÉ (REPONSE_REGISTRE_INVALIDE) | ✔ | ✔ | ✔ | ✔ | – | oui |

✔ contrôle réussi · ✘ contrôle échoué · – non effectué ou indéterminé
