# Structure du Projet NTLM Relay Tool

## 1. Introduction et Contexte

### Présentation du projet
Le NTLM Relay Tool est un framework de cybersécurité spécialisé conçu pour tester, analyser et démontrer les vulnérabilités d'authentification NTLM dans les environnements réseau Windows. Il implémente une solution complète pour capturer les tentatives d'authentification NTLM, empoisonner les protocoles de résolution de noms, relayer les identifiants vers des services cibles, et optionnellement cracker les hachages - tout en fournissant des capacités robustes de stockage, de journalisation et d'analyse.

### Objectifs et portée
Le NTLM Relay Tool répond au défi persistant de sécurité posé par la vulnérabilité du protocole d'authentification NTLM aux attaques de relais. Malgré son remplacement progressif par Kerberos, NTLM reste largement utilisé dans de nombreuses organisations, particulièrement dans les systèmes hérités et les environnements mixtes.

L'outil offre :
- Une implémentation complète des techniques de relais NTLM
- Plusieurs modes d'opération (capture, poison, relay)
- Persistance des données dans une base de données pour analyse et rapports
- Options de configuration avancées pour différents scénarios de test
- Capacités détaillées de journalisation et d'analyse

### Public cible
L'outil est conçu pour :
- Les professionnels de la sécurité effectuant des tests de pénétration autorisés
- Les administrateurs réseau validant les contrôles de sécurité
- Les formateurs en sécurité démontrant les vulnérabilités NTLM
- Les équipes rouges effectuant des simulations d'attaques contrôlées

## 2. Analyse des Besoins

### Recueil des exigences
Les exigences principales du projet incluent :
- Capacité à capturer passivement le trafic d'authentification NTLM
- Fonctionnalités d'empoisonnement réseau pour déclencher des authentifications NTLM
- Mécanismes de relais pour transmettre les authentifications vers des cibles spécifiques
- Stockage persistant des données capturées pour analyse
- Interface de ligne de commande intuitive avec différents modes d'opération
- Journalisation détaillée pour l'audit et le débogage
- Support multi-plateforme (Windows, Linux)

### Identification des parties prenantes
- Équipes de sécurité informatique
- Administrateurs réseau
- Consultants en tests de pénétration
- Développeurs de solutions de sécurité
- Chercheurs en sécurité informatique

### Contexte technique et fonctionnel
Le projet s'appuie sur :
- Python 3.11+ comme langage principal
- Impacket pour l'implémentation du protocole NTLM
- Scapy pour la capture et l'analyse de paquets
- MongoDB pour le stockage des données
- Bibliothèques cryptographiques pour le traitement des hachages
- Sockets réseau bruts pour les fonctionnalités d'empoisonnement

## 3. Planification du Projet

### Décomposition en étapes clés
1. **Phase d'analyse et conception**
   - Étude du protocole NTLM et des vulnérabilités associées
   - Conception de l'architecture modulaire
   - Définition des interfaces entre composants

2. **Phase de développement**
   - Implémentation du module de capture
   - Implémentation du module d'empoisonnement
   - Implémentation du module de relais
   - Implémentation du module de stockage
   - Développement des utilitaires communs

3. **Phase de test**
   - Tests unitaires des composants individuels
   - Tests d'intégration des modules interconnectés
   - Tests fonctionnels de bout en bout
   - Tests de performance et de charge

4. **Phase de documentation**
   - Rédaction de la documentation technique
   - Création du guide utilisateur
   - Documentation du code source

5. **Phase de déploiement**
   - Préparation des packages d'installation
   - Test de déploiement sur différents environnements
   - Résolution des problèmes de compatibilité

### Description des jalons importants
- **Jalon 1**: Architecture et conception validées
- **Jalon 2**: Modules de base implémentés et testés individuellement
- **Jalon 3**: Intégration complète des modules
- **Jalon 4**: Tests de bout en bout réussis
- **Jalon 5**: Documentation complétée
- **Jalon 6**: Version stable prête pour le déploiement

### Estimation des délais et répartition des ressources
- **Phase d'analyse et conception**: 3 semaines
- **Phase de développement**: 8 semaines
  - Module de capture: 2 semaines
  - Module d'empoisonnement: 2 semaines
  - Module de relais: 2 semaines
  - Module de stockage: 1 semaine
  - Utilitaires communs: 1 semaine
- **Phase de test**: 3 semaines
- **Phase de documentation**: 2 semaines
- **Phase de déploiement**: 1 semaine

**Ressources nécessaires**:
- 2 développeurs spécialisés en sécurité
- 1 testeur en sécurité
- 1 rédacteur technique
- Environnements de test (Windows et Linux)

## 4. Architecture et Conception

### Description de l'architecture globale
L'architecture du NTLM Relay Tool suit une conception modulaire avec une séparation claire des responsabilités:

```
┌─────────────────┐         ┌──────────────────┐         ┌─────────────────┐
│   Capture/      │         │     Exploit      │         │    Storage      │
│   Poison        │───────▶│     Module       │───────▶│    Module       │
│   Module        │         │                  │         │                 │
└─────────────────┘         └──────────────────┘         └─────────────────┘
        ▲                           ▲                            ▲
        │                           │                            │
        └───────────────┬───────────┴────────────┬──────────────┘
                        │                        │
                        ▼                        ▼
              ┌─────────────────┐     ┌───────────────────┐
              │  Configuration  │     │     Utilities     │
              │     Module      │     │                   │
              └─────────────────┘     └───────────────────┘
```

Le flux de données suit ce parcours:
1. L'utilisateur configure et lance l'outil dans un mode spécifique
2. Le module Capture/Poison collecte ou déclenche des tentatives d'authentification NTLM
3. Les données d'authentification sont optionnellement relayées vers des services cibles
4. Les résultats (authentifications réussies/échouées) sont stockés dans MongoDB
5. Les données sont disponibles pour examen, analyse et rapports

### Diagrammes (UML, flux, etc.)
**Diagramme de classes simplifié**:
```
┌────────────────┐     ┌────────────────┐     ┌────────────────┐
│ ResponderCapture│     │     Relay      │     │  MongoDBHandler│
├────────────────┤     ├────────────────┤     ├────────────────┤
│ start_poisoning()│     │ start_relay()  │     │ store_capture()│
│ stop_poisoning() │     │ stop_relay()   │     │ get_captures() │
└────────────────┘     └────────────────┘     └────────────────┘
        ▲                      ▲                      ▲
        │                      │                      │
        │                      │                      │
        │                      ▼                      │
┌────────────────┐     ┌────────────────┐            │
│  PacketSniffer  │     │NTLMRelayServer │            │
├────────────────┤     ├────────────────┤            │
│ start()         │     │ start()        │            │
│ stop()          │     │ stop()         │            │
└────────────────┘     └────────────────┘            │
        │                      │                      │
        │                      │                      │
        ▼                      ▼                      ▼
┌────────────────────────────────────────────────────────────┐
│                           Main                              │
├────────────────────────────────────────────────────────────┤
│ setup_logging()                                             │
│ list_interfaces()                                           │
│ list_results()                                              │
└────────────────────────────────────────────────────────────┘
```

**Diagramme de cas d'utilisation**:
```
┌────────────────────────────────────────────────────────────┐
│                   NTLM Relay Tool                           │
│                                                            │
│  ┌───────────┐    ┌───────────┐     ┌───────────┐         │
│  │  View     │    │  Poison   │     │  Relay    │         │
│  │ Interfaces│    │  Network  │     │  Auth     │         │
│  └───────────┘    └───────────┘     └───────────┘         │
│        ▲                ▲                 ▲               │
│        │                │                 │               │
│        │                │                 │               │
└────────┼────────────────┼─────────────────┼───────────────┘
         │                │                 │
         │                │                 │
         ▼                ▼                 ▼
     ┌───────────────────────────────────────────┐
     │             Analyste de Sécurité          │
     └───────────────────────────────────────────┘
```

### Décisions techniques majeures et choix des technologies
- **Python**: Choisi pour sa flexibilité, sa lisibilité et ses nombreuses bibliothèques de sécurité et réseau
- **Impacket**: Bibliothèque spécialisée dans l'implémentation des protocoles de réseau Microsoft
- **Scapy**: Puissant framework de manipulation et capture de paquets
- **MongoDB**: Base de données NoSQL offrant flexibilité pour le stockage des données de capture
- **Architecture modulaire**: Permet l'extension future et la maintenance simplifiée
- **Ligne de commande**: Interface privilégiée pour les outils de sécurité et leur automatisation

## 5. Développement et Implémentation

### Mise en place de l'environnement de développement
L'environnement de développement nécessite:
- Python 3.11+
- Dépendances listées dans requirements.txt
- MongoDB pour le stockage
- Environnement virtuel Python pour l'isolation
- Privilèges administrateur/root pour la capture de paquets et l'empoisonnement réseau
- Outils de test (pytest, coverage)

### Stratégie d'implémentation étape par étape
1. **Installation et configuration**:
   ```bash
   git clone https://github.com/your-org/ntlmrelaytool.git
   cd ntlmrelaytool
   python -m venv venv
   # Activation de l'environnement virtuel (varie selon OS)
   pip install -r requirements.txt
   ```

2. **Configuration**:
   - Créer les fichiers de configuration dans le dossier `config/`
   - Configurer MongoDB selon vos besoins

3. **Utilisation**:
   - **Mode Empoisonnement**:
     ```bash
     python src/main.py poison --interface <interface_réseau>
     ```
   - **Mode Relais**:
     ```bash
     python src/main.py relay --interface <interface_réseau> --target <adresse_cible>
     ```
   - **Mode Attaque Combinée**:
     ```bash
     python src/main.py attack --interface <interface_réseau> --target <adresse_cible>
     ```
   - **Listage des Résultats**:
     ```bash
     python src/main.py list
     ```

### Principales fonctionnalités et modules
1. **Module de capture (src/modules/capture)**:
   - `parser.py`: Extraction et traitement des données d'authentification NTLM
   - `responder.py`: Implémentation de techniques d'empoisonnement actif

2. **Module d'exploitation (src/modules/exploit)**:
   - `relay.py`: Transfert des authentifications capturées vers les services cibles
   - `ntlmrelayserver.py`: Gestion des détails techniques du protocole SMB
   - `cracker.py`: Tentative de récupération des mots de passe en clair

3. **Module de stockage (src/modules/storage)**:
   - `database.py`: Abstraction des opérations de base de données
   - `models.py`: Définition des structures de données

4. **Utilitaires (src/utils)**:
   - `config.py`: Chargement et gestion des paramètres
   - `hash_handler.py`: Traitement des hachages NTLM
   - `mongo_handler.py`: Gestion de la connexion MongoDB
   - `packet_sniffer.py`: Capture du trafic réseau
   - `logger.py`: Journalisation centralisée

5. **Contrôleur principal (src/main.py)**:
   - Orchestration de tous les composants
   - Traitement des arguments de ligne de commande
   - Gestion du cycle de vie des composants
   - Coordination du flux de données entre composants

## 6. Tests et Validation

### Stratégie de test (unitaires, d'intégration, etc.)
La stratégie de test comprend:

1. **Tests unitaires**:
   - Tests des composants individuels
   - Utilisation de pytest comme framework de test
   - Mocking des dépendances externes

2. **Tests d'intégration**:
   - Tests des interactions entre composants
   - Validation du flux de données de bout en bout
   - Vérification des interfaces entre modules

3. **Tests fonctionnels**:
   - Tests des scénarios d'utilisation complets
   - Validation des fonctionnalités de l'interface utilisateur
   - Tests sur différentes plateformes (Windows, Linux)

4. **Tests de performance**:
   - Benchmarking des opérations critiques
   - Tests de charge pour les composants réseau et base de données
   - Évaluation de la consommation de ressources

### Gestion des retours et correction des anomalies
Le processus de gestion des anomalies comprend:
- Journalisation détaillée pour faciliter le diagnostic
- Traçabilité des exceptions à travers les différentes couches
- Mécanismes de reprise après erreur
- Dégradation élégante en cas de défaillance de composants
- Documentation des erreurs connues et leurs solutions

### Critères de validation et recette
Les critères de validation incluent:
- Couverture de code > 80%
- Tous les tests unitaires et d'intégration passent
- Absence de fuites mémoire
- Réussite des tests fonctionnels sur toutes les plateformes supportées
- Validation manuelle des scénarios critiques
- Documentation complète et à jour

## 7. Déploiement et Mise en Production

### Stratégie de déploiement
La stratégie de déploiement comprend:
1. **Packaging**:
   - Création d'un package PyPI pour installation facile
   - Distribution des binaires pour les plateformes principales

2. **Installation**:
   - Via pip: `pip install ntlmrelaytool`
   - Installation manuelle depuis les sources
   - Vérification des dépendances

3. **Vérification post-déploiement**:
   - Tests de smoke pour vérifier l'installation
   - Validation des configurations par défaut
   - Vérification de l'accès à la base de données

### Configuration des environnements (staging, production)
1. **Environnement de développement**:
   - Configuration locale MongoDB
   - Journalisation verbeuse
   - Fichiers de configuration de développement

2. **Environnement de test/staging**:
   - Base de données de test isolée
   - Journalisation détaillée
   - Simulation des scénarios de production

3. **Environnement de production**:
   - Base de données de production sécurisée
   - Journalisation optimisée
   - Configuration minimale nécessaire

### Procédures de maintenance et mises à jour
1. **Mises à jour**:
   - Publication régulière des versions sur GitHub/PyPI
   - Notes de version détaillées
   - Scripts de migration pour les changements de schéma

2. **Maintenance**:
   - Procédure de sauvegarde de la base de données
   - Rotation et archivage des journaux
   - Nettoyage des données temporaires

3. **Résolution des problèmes**:
   - Guide de dépannage
   - Outils de diagnostic inclus
   - Support communautaire via GitHub Issues

## 8. Documentation et Formation

### Guides utilisateurs et développeurs
1. **Documentation utilisateur**:
   - Guide d'installation
   - Guide de démarrage rapide
   - Manuel de référence des commandes
   - Tutoriels pour les cas d'utilisation courants

2. **Documentation technique**:
   - Architecture détaillée
   - Principes de conception
   - Documentation de l'API
   - Guide de contribution

3. **Documentation du code source**:
   - Docstrings Python pour l'auto-documentation
   - Commentaires explicatifs pour les sections complexes
   - Exemples d'utilisation des classes principales

### Plan de formation
1. **Formation de base**:
   - Installation et configuration
   - Utilisation des modes principaux
   - Interprétation des résultats

2. **Formation avancée**:
   - Personnalisation et extension
   - Intégration avec d'autres outils
   - Techniques avancées de relais NTLM

3. **Formation pour développeurs**:
   - Structure du code et architecture
   - Ajout de nouveaux modules
   - Contribution au projet

### FAQ et support technique
1. **FAQ**:
   - Problèmes courants et solutions
   - Limitations connues
   - Questions de compatibilité

2. **Support**:
   - Canal de support via GitHub Issues
   - Documentation de dépannage
   - Communauté Discord ou Slack

3. **Ressources additionnelles**:
   - Articles sur le protocole NTLM
   - Références aux CVE pertinentes
   - Liens vers des outils complémentaires

## Conclusion

Le NTLM Relay Tool est un framework complet pour tester et valider la sécurité de l'authentification NTLM. Sa conception modulaire, ses options de configuration étendues et sa journalisation détaillée en font un outil précieux pour les professionnels de la sécurité. En suivant les directives d'utilisation appropriées et les considérations légales, les organisations peuvent utiliser cet outil pour améliorer leur posture de sécurité face aux attaques de relais NTLM.

Ce document présente la structure complète du projet, de sa conception à son déploiement, en passant par le développement, les tests et la documentation. Chaque section détaille les aspects importants à considérer pour une mise en œuvre réussie du projet.

_Document réalisé le 8 mai 2025_