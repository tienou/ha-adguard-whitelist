# AdGuard Whitelist - Sites Autorisés

[![hacs_badge](https://img.shields.io/badge/HACS-Custom-41BDF5.svg)](https://github.com/hacs/integration)

Intégration Home Assistant pour gérer la liste blanche AdGuard Home directement depuis votre dashboard.

## Fonctionnalités

- **Ajouter / supprimer des sites** depuis une carte Lovelace ou via les services HA
- **Switches dynamiques** : un switch par site autorisé (toggle OFF = suppression)
- **Catégorisation automatique** : Éducation, Programmation, CDN/Technique, Autre
- **Synchro Firefox** (optionnel) : ajoute/supprime les bookmarks dans `policies.json` via SSH
- **File d'attente offline** : si le PC cible est éteint, les modifications Firefox sont rejouées automatiquement

## Installation via HACS

1. Ouvrir HACS dans Home Assistant
2. Cliquer sur les 3 points en haut à droite → **Dépôts personnalisés**
3. Ajouter `https://github.com/tienou/ha-adguard-whitelist` avec la catégorie **Intégration**
4. Installer "AdGuard Whitelist - Sites Autorisés"
5. Redémarrer Home Assistant

## Configuration

1. **Paramètres** → **Intégrations** → **Ajouter une intégration**
2. Rechercher "AdGuard Whitelist"
3. Renseigner :
   - URL AdGuard Home (ex: `http://192.168.8.1:3000`)
   - Identifiants AdGuard
   - IP du client à gérer (ex: `192.168.8.50`)
4. (Optionnel) Activer la synchronisation des bookmarks Firefox via SSH

## Carte Lovelace

Ajouter au dashboard :

```yaml
type: custom:adguard-whitelist-card
client_ip: "192.168.8.50"
```

Options :

| Option | Défaut | Description |
|--------|--------|-------------|
| `client_ip` | *requis* | IP du client |
| `title` | "Sites Autorisés" | Titre de la carte |
| `show_cdn` | `true` | Afficher les domaines CDN/techniques |

## Services

| Service | Description |
|---------|-------------|
| `adguard_whitelist.add_site` | Ajouter un domaine à la liste blanche |
| `adguard_whitelist.remove_site` | Supprimer un domaine de la liste blanche |

Exemple d'appel :

```yaml
service: adguard_whitelist.add_site
data:
  domain: "lumni.fr"
```

## Fonctionnement

L'intégration utilise l'API REST d'AdGuard Home :
- `GET /control/filtering/status` pour lire les règles
- `POST /control/filtering/set_rules` pour les modifier

Seules les règles `@@||domaine^$client='IP'` correspondant à l'IP configurée sont touchées. Toutes les autres règles (commentaires, CDN, autres clients, blocages) sont préservées intégralement.
