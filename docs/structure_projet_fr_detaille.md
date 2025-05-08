# Structure Détaillée du Projet NTLM Relay Tool

## 1. Introduction et Contexte

Le NTLM Relay Tool est un outil de sécurité offensive permettant de capturer, relayer et analyser les authentifications NTLM sur un réseau. Il s’adresse aux professionnels de la sécurité, aux administrateurs réseau et aux équipes de tests d’intrusion.

## 2. Analyse des Besoins

- **Exigences fonctionnelles** :
  - Capturer le trafic NTLM sur différentes interfaces réseau.
  - Réaliser des attaques de type "relay" sur SMB, HTTP, LDAP.
  - Stocker les résultats dans une base MongoDB.
  - Fournir une interface CLI simple et des logs détaillés.
- **Exigences techniques** :
  - Support Windows et Linux.
  - Utilisation de Python 3.11+, Scapy, Impacket, PyMongo.
  - Privilèges administrateur/root requis pour certaines opérations.

## 3. Planification et Organisation

- **Étapes principales** :
  1. Étude du protocole NTLM et des attaques relay.
  2. Conception de l’architecture modulaire (capture, exploit, stockage, utils).
  3. Développement incrémental de chaque module.
  4. Rédaction de la documentation technique et utilisateur.
  5. Tests unitaires, d’intégration et fonctionnels.
  6. Déploiement et maintenance.

- **Conseil** : Utiliser un gestionnaire de versions (Git) et des issues pour suivre l’avancement.

## 4. Architecture et Conception

- **Modules principaux** :
  - `capture/` :
    - `parser.py` : Extraction des messages NTLM des paquets réseau.
    - `responder.py` : Serveurs d’empoisonnement LLMNR/NBT-NS/MDNS, HTTP et SMB.
  - `exploit/` :
    - `relay.py` : Logique de relais NTLM.
    - `ntlmrelayserver.py` : Orchestration du protocole SMB.
    - `cracker.py` : Brute-force des hachages NTLM.
  - `storage/` :
    - `database.py` : Abstraction de la base de données.
    - `models.py` : Modèles de données (cibles, captures, plugins, utilisateurs).
  - `utils/` :
    - `config.py`, `logger.py`, `mongo_handler.py`, `hash_handler.py`, `packet_sniffer.py`.
  - `main.py` : Point d’entrée CLI, gestion des arguments et de l’orchestration.

- **Exemple de flux** :
  1. Lancement en mode `poison` : le serveur écoute et empoisonne le réseau.
  2. Lancement en mode `relay` : le serveur relaie les authentifications vers une cible.
  3. Les résultats sont stockés dans MongoDB et consultables via la commande `list`.

## 5. Développement et Implémentation

- **Installation** :
  ```bash
  git clone https://github.com/your-org/ntlmrelaytool.git
  cd ntlmrelaytool
  python -m venv venv
  venv\Scripts\activate  # Sous Windows
  pip install -r requirements.txt
  ```
- **Configuration** :
  - Adapter `config/mongodb.ini` selon votre environnement.
  - Vérifier les droits administrateur pour la capture réseau.
- **Bonnes pratiques** :
  - Ajouter des docstrings et des logs dans chaque fonction.
  - Utiliser des exceptions personnalisées pour la gestion des erreurs critiques.

## 6. Tests et Validation

- **Tests unitaires** :
  - Placer les tests dans le dossier `tests/`.
  - Exemple : `pytest tests/test_exploit.py`.
- **Tests d’intégration** :
  - Simuler des flux réseau avec des VM ou des environnements isolés.
- **Critères de validation** :
  - Tous les modes fonctionnent sur Windows et Linux.
  - Les logs et la base MongoDB reçoivent bien les événements.

## 7. Déploiement et Maintenance

- **Déploiement** :
  - Utiliser un environnement virtuel dédié.
  - Documenter la procédure d’installation pour les utilisateurs finaux.
- **Maintenance** :
  - Mettre à jour régulièrement les dépendances (requirements.txt).
  - Archiver les logs et sauvegarder la base MongoDB.

## 8. Documentation et Formation

- **Guide utilisateur** :
  - Expliquer chaque commande avec exemples (`poison`, `relay`, `attack`, `list`).
  - Ajouter une FAQ pour les erreurs courantes (problèmes de droits, de dépendances, etc).
- **Guide développeur** :
  - Décrire la structure du code et les conventions de nommage.
  - Expliquer comment ajouter un nouveau module ou une nouvelle fonctionnalité.

## 9. Conseils pratiques

- Toujours tester sur un environnement isolé.
- Ne jamais utiliser l’outil sans autorisation explicite.
- Lire les logs (`ntlm_relay.log`, `app.log`) pour diagnostiquer les problèmes.
- Consulter la documentation technique (`docs/technical.md`) pour approfondir.

---

Ce document détaille chaque étape de la réalisation du projet NTLM Relay Tool, avec des exemples concrets et des conseils pour garantir une implémentation réussie.
