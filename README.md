# AdGuard Whitelist - Sites Autorisés

[![hacs_badge](https://img.shields.io/badge/HACS-Custom-41BDF5.svg)](https://github.com/hacs/integration)
[![GitHub release](https://img.shields.io/github/v/release/tienou/ha-adguard-whitelist)](https://github.com/tienou/ha-adguard-whitelist/releases)

Intégration Home Assistant pour gérer la liste blanche AdGuard Home directement depuis votre dashboard. Pensée pour le contrôle parental : autorisez ou bloquez des sites pour un appareil spécifique sans toucher à l'interface AdGuard.

## Fonctionnalités

- **Carte Lovelace intégrée** avec autocomplete (130+ domaines), catégories triées, et dialog d'ajout
- **Dialog d'ajout** : choix de la catégorie + option de créer un raccourci Firefox
- **Catégorisation** : Éducation, Programmation, CDN/Technique, Autre (+ catégories personnalisées)
- **Icône Firefox** à côté des sites qui ont un raccourci dans le navigateur
- **Switches dynamiques** : un switch par site autorisé (toggle OFF = suppression)
- **Synchro Firefox** (optionnel) : ajoute/supprime les bookmarks dans `policies.json` via SSH
- **Détection des bookmarks existants** : lit le `policies.json` distant pour afficher les icônes Firefox même pour les sites ajoutés avant l'intégration
- **File d'attente offline** : si le PC cible est éteint, les modifications Firefox sont mises en queue et rejouées automatiquement
- **Options flow** : modifiez les identifiants AdGuard et SSH après l'installation

## Installation via HACS

1. Ouvrir HACS dans Home Assistant
2. Cliquer sur les 3 points en haut à droite > **Dépôts personnalisés**
3. Ajouter `https://github.com/tienou/ha-adguard-whitelist` avec la catégorie **Intégration**
4. Installer "AdGuard Whitelist - Sites Autorisés"
5. Redémarrer Home Assistant

## Configuration

1. **Paramètres** > **Intégrations** > **Ajouter une intégration**
2. Rechercher "AdGuard Whitelist"
3. Renseigner :
   - URL AdGuard Home (ex: `http://192.168.8.1:3000`)
   - Identifiants AdGuard
   - IP du client (ex: `192.168.8.50`)
4. (Optionnel) Activer la synchronisation des bookmarks Firefox via SSH :
   - Hôte SSH (IP du PC)
   - Port (défaut: 22)
   - Utilisateur / Mot de passe

## Carte Lovelace

La carte est automatiquement disponible dans le sélecteur de cartes. Configuration manuelle :

```yaml
type: custom:adguard-whitelist-card
client_ip: "192.168.8.50"
```

| Option | Défaut | Description |
|--------|--------|-------------|
| `client_ip` | *requis* | IP du client AdGuard |
| `title` | "Sites Autorisés" | Titre de la carte |
| `show_cdn` | `true` | Afficher les domaines CDN/techniques |

### Fonctionnalités de la carte

- **Autocomplete** : tapez un domaine et choisissez parmi les suggestions
- **Dialog d'ajout** : cliquez "Ajouter" pour choisir la catégorie et l'option Firefox
- **Catégories triées** : Éducation et Programmation en premier, Autre et CDN en dernier
- **Icône Firefox** : les sites avec un raccourci Firefox affichent l'icône du navigateur
- **Suppression** : cliquez le bouton rouge pour retirer un site (avec confirmation)

## Services

| Service | Paramètres | Description |
|---------|------------|-------------|
| `adguard_whitelist.add_site` | `domain` (requis), `category`, `create_bookmark` | Ajouter un site |
| `adguard_whitelist.remove_site` | `domain` (requis) | Supprimer un site |

Exemples :

```yaml
# Ajout simple
service: adguard_whitelist.add_site
data:
  domain: "lumni.fr"

# Ajout avec catégorie et bookmark Firefox
service: adguard_whitelist.add_site
data:
  domain: "scratch.mit.edu"
  category: "Programmation"
  create_bookmark: true
```

## Entités

| Entité | Type | Description |
|--------|------|-------------|
| `sensor.filtrage_dns_*_sites_autorises` | Sensor | Nombre de sites autorisés |
| `switch.filtrage_dns_*_<domaine>` | Switch | Toggle par site (OFF = supprimer) |

### Attributs du sensor

| Attribut | Description |
|----------|-------------|
| `domains` | Liste de tous les domaines autorisés |
| `total_rules` | Nombre total de règles AdGuard |
| `pending_ssh` | Nombre de commandes SSH en attente |
| `bookmarked_domains` | Domaines ayant un raccourci Firefox |
| `ssh_enabled` | SSH Firefox activé ou non |
| `category_*` | Domaines par catégorie |

## Fonctionnement technique

L'intégration utilise l'API REST d'AdGuard Home :
- `GET /control/filtering/status` pour lire les règles
- `POST /control/filtering/set_rules` pour les modifier

Seules les règles `@@||domaine^$client='IP'` correspondant au client configuré sont touchées. Toutes les autres règles (commentaires, CDN, autres clients, blocages) sont intégralement préservées.

La synchronisation Firefox modifie `/usr/lib/firefox/distribution/policies.json` via SSH avec sudo. Les métadonnées (catégorie, bookmark) sont persistées localement via le Store HA.
