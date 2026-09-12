*[Read this in English](README.en.md)*

# Hangar

Gestionnaire d'artefacts auto-hébergé — un registre npm et un registre
Docker/OCI derrière une seule console d'administration, un seul système
d'authentification, et un seul jeu de contrôles de gouvernance (quotas,
rétention, RBAC, audit).

Backend Rust en architecture hexagonale/DDD (`hangar-domain` →
`hangar-application` → `hangar-infrastructure`/`hangar-api`, plus les
crates adaptateurs de protocole `hangar-npm` et `hangar-docker`), avec un
frontend Angular 22 servi par le même binaire.

## Sommaire

- [Fonctionnalités](#fonctionnalités)
- [Architecture](#architecture)
- [Stack technique](#stack-technique)
- [Lancer le projet en local](#lancer-le-projet-en-local)
- [Déploiement](#déploiement)
- [Référence de configuration](#référence-de-configuration)
- [Sécurité](#sécurité)
- [Comparaison avec les alternatives](#comparaison-avec-les-alternatives)
- [Feuille de route](#feuille-de-route)
- [Licence](#licence)

## Fonctionnalités

**Registres**
- Protocole de registre npm (publish, install, unpublish, dist-tags)
- Protocole de registre Docker/OCI (push, pull, suppression de manifest)
- Trois types de dépôt par format : **hosted** (contenu que vous hébergez),
  **proxy** (cache transparent devant un registre amont, ex. npmjs.org ou
  Docker Hub), **group** (agrège plusieurs dépôts derrière un seul point
  d'entrée)
- Quotas de stockage par dépôt
- Politique de rétention par dépôt (conserver les N dernières
  versions/étiquettes par paquet/image ; les références taguées comme
  `latest` ne sont jamais purgées) — purge automatique toutes les 6 heures
- Navigateur de paquets/images avec vue détaillée par paquet

**Scan de sécurité**
- Audit des dépendances npm contre la base d'avis publique, déclenché
  automatiquement à chaque publication
- Scan de vulnérabilités des images Docker via
  [Trivy](https://github.com/aquasecurity/trivy), déclenché automatiquement
  à chaque push, plus relance manuelle

**Multi-tenant**
- Organisations résolues par sous-domaine (`acme.hangar.example` route vers
  l'organisation `acme`), chacune avec ses propres dépôts, utilisateurs et
  marque
- Admins d'organisation aux droits scopés à leur seule organisation ; un
  super-admin peut cibler n'importe quelle organisation via
  `?organization_id=`
- Organisation publique par défaut pour les déploiements mono-tenant

**Authentification & contrôle d'accès**
- Comptes locaux avec hachage de mot de passe Argon2
- SSO : LDAP/Active Directory et OIDC (OpenID Connect), en plus des comptes
  locaux — SAML n'est pas encore supporté
- Double authentification obligatoire : TOTP ou clé d'accès (WebAuthn/
  passkey), avec codes de secours à usage unique
- Tokens API personnels (portée par utilisateur ; les admins peuvent lister
  et révoquer les tokens de tous les utilisateurs)
- RBAC par dépôt (`read` / `write` / `admin`), attribué par utilisateur
- Invitations de compte par e-mail et parcours d'activation
- Limitation des tentatives de connexion échouées (par processus)

**Console d'administration**
- Métriques d'usage, historique horodaté (snapshots horaires), page d'état
  de santé
- Journal d'audit et journal des événements de sécurité
- Gestion des utilisateurs (création, suppression, promotion super-admin)
- Paramètres SMTP (hôte/port/identifiants/sécurité/nom et adresse
  d'expéditeur) avec bouton d'envoi d'e-mail de test
- Marque personnalisée : remplacer le logo/favicon par défaut partout
  (interface + e-mails), pour du marque blanche ou des déploiements en
  cluster isolé
- Export/import de configuration pour sauvegarde et restauration
- E-mails transactionnels HTML (compte créé, mot de passe régénéré,
  MFA/passkey ajouté) avec la marque du déploiement intégrée en ligne (CID,
  donc affichée même quand les images externes sont bloquées)

## Architecture

Hexagonale/DDD, les dépendances pointent vers l'intérieur :

| Crate | Rôle |
|---|---|
| `hangar-domain` | Entités, objets de valeur, ports (traits) — aucune dépendance vers un framework ou une I/O |
| `hangar-application` | Cas d'usage, orchestrant la logique métier via les ports |
| `hangar-infrastructure` | Implémentations des ports : Postgres, stockage fichier, SMTP, Trivy, Argon2, JWT |
| `hangar-api` | Serveur HTTP Axum, handlers/DTO des routes, assemble tout, sert le frontend compilé |
| `hangar-npm` | Adaptateur du protocole de registre npm (son propre jeu de routes, monté dans `hangar-api`) |
| `hangar-docker` | Adaptateur du protocole de registre Docker/OCI (même principe) |

Les dépôts (`PackageRepository`) et les permissions sont en event-sourcing ;
le reste de l'état (utilisateurs, paramètres, journal d'audit, métriques)
est du CRUD classique sur Postgres.

## Stack technique

- **Backend :** Rust (édition 2024), [Axum](https://github.com/tokio-rs/axum), [SQLx](https://github.com/launchbadge/sqlx) + Postgres, [webauthn-rs](https://github.com/kanidm/webauthn-rs), [lettre](https://github.com/lettre/lettre)
- **Frontend :** Angular 22, composants standalone, signals (pas de NgRx)
- **Stockage :** système de fichiers local (`StorageBackendPort` est abstrait, mais seule une implémentation fichier existe aujourd'hui — voir la [feuille de route](#feuille-de-route))

## Lancer le projet en local

```bash
git clone <ce-repo>
cd hangar
cp .env.example .env   # renseigner POSTGRES_PASSWORD / JWT_SECRET
./scripts/dev.sh
```

Ceci démarre Postgres via `docker-compose`, applique les migrations, puis
lance le backend (`cargo run -p hangar-api`, port 8081) et le frontend
(`ng serve`, port 4200, hot reload) en parallèle. `scripts/dev.sh` fixe
`HANGAR_BOOTSTRAP_ADMIN_USERNAME=admin` /
`HANGAR_BOOTSTRAP_ADMIN_PASSWORD=admin123`, donc vous pouvez vous connecter
immédiatement.

Lancer les tests :

```bash
cargo test --workspace                  # backend
npm test --prefix frontend              # frontend
```

## Déploiement

### Docker Compose

Un déploiement mono-nœud (Hangar + Postgres) tient en une commande :

```bash
cp .env.example .env   # renseigner POSTGRES_PASSWORD, JWT_SECRET, HANGAR_BOOTSTRAP_ADMIN_*
docker compose up -d --build
```

Voir la [référence de configuration](#référence-de-configuration)
ci-dessous pour chaque variable câblée par `docker-compose.yml`, et en
particulier `HANGAR_DOCKER_TOKEN_REALM` — le protocole Docker ne
fonctionnera pour aucun client extérieur au conteneur tant que cette
variable ne pointe pas vers une URL réellement joignable par le CLI
`docker`.

> Déploiement Kubernetes/Helm : à documenter ultérieurement.

## Référence de configuration

Chaque variable lue par `hangar-api` depuis son environnement.
`docker-compose.yml` câble déjà celles nécessaires à un déploiement
mono-nœud ; ce tableau fait référence pour un déploiement conteneur nu ou
pour surcharger les valeurs par défaut.

| Variable | Obligatoire | Défaut | Description |
|---|---|---|---|
| `DATABASE_URL` | **Oui** | — | Chaîne de connexion Postgres, ex. `postgres://user:pass@host:5432/hangar`. |
| `JWT_SECRET` | **Oui** | — | Signe les tokens de session et les tokens d'accès au registre Docker. Doit être long, aléatoire, secret. Le faire tourner invalide toutes les sessions et tous les `docker login`. |
| `HANGAR_BASE_DOMAIN` | **Oui** | — | Domaine de base par rapport auquel les organisations sont résolues en sous-domaines (ex. `hangar.example` pour que `acme.hangar.example` résolve l'organisation `acme`). Aucun fallback : un déploiement mal configuré doit échouer au démarrage plutôt que de router silencieusement tous les sous-domaines vers l'organisation publique. |
| `STORAGE_ROOT` | Non | `./data` | Chemin du système de fichiers où sont stockés les tarballs npm et les blobs Docker. Doit être un volume persistant dans tout déploiement réel. |
| `BIND_ADDR` | Non | `0.0.0.0:8080` | Adresse/port sur lequel le serveur HTTP écoute. |
| `STATIC_DIR` | Non | `./static` | Chemin des assets frontend compilés servis pour les routes non-API. Pertinent uniquement si vous n'utilisez pas l'image Docker fournie. |
| `RUST_LOG` | Non | — (aucun log sans elle) | Filtre `tracing_subscriber`, ex. `info` ou `hangar_api=debug,info`. Sans elle, le conteneur ne log quasiment rien. |
| `CORS_ALLOWED_ORIGIN` | Non | permissif (toute origine) | Restreint le CORS à une seule origine. À laisser vide en dev local (`ng serve` sur un port différent du backend) ou quand le frontend est servi depuis la même origine que l'API (configuration par défaut de l'image fournie). |
| `HANGAR_DOCKER_TOKEN_REALM` | En pratique oui, pour Docker | dérivée de `BIND_ADDR` (`http://0.0.0.0:8080/v2/token` — injoignable depuis l'extérieur du conteneur) | URL absolue du endpoint `/v2/token` de ce déploiement, intégrée dans chaque challenge `WWW-Authenticate`. Le CLI Docker résout dessus les requêtes de token pour `login`/`push`/`pull` — une mauvaise valeur casse tout le flux d'authentification Docker pour les clients réels. Doit être en `https://` pour tout hôte non-localhost (Docker refuse le `http://` simple sinon). |
| `PUBLIC_URL` | En pratique oui, dès qu'on utilise les invitations | dérivée de `BIND_ADDR` (même souci de non-joignabilité) | URL de base sur laquelle sont construits les liens d'invitation de compte. Doit être joignable depuis le client mail du destinataire. |
| `HANGAR_BOOTSTRAP_ADMIN_USERNAME` | Non | — | Nom d'utilisateur du compte créé automatiquement **uniquement si la table `users` est vide**. Peut rester défini au fil des redémarrages/mises à jour. |
| `HANGAR_BOOTSTRAP_ADMIN_PASSWORD` | Non, mais il faut *un* moyen d'obtenir un premier admin | — | Mot de passe de ce même compte bootstrap. Doit faire ≥ 8 caractères — une valeur plus courte échoue silencieusement (loggé, non fatal) et laisse le déploiement sans admin. |

`HANGAR_DOCKER_TOKEN_REALM` et `PUBLIC_URL` retombent tous deux sur une
URL devinée à partir de `BIND_ADDR`, ce qui n'est correct que pour un
déploiement exposé directement, sans reverse proxy ni terminaison TLS —
à définir explicitement dans tous les autres cas.

**Non configurable via l'environnement aujourd'hui** (codé en dur) : la
purge des métriques (horaire) et la purge de rétention (toutes les
6 heures). Le scanner d'images Docker exécute un binaire `trivy` qui doit
être présent dans le `PATH` (le Dockerfile fourni l'installe ; une image
personnalisée devra l'installer aussi).

## Sécurité

- Hachage de mot de passe Argon2
- MFA obligatoire (TOTP ou WebAuthn/passkey) avec codes de secours à usage
  unique
- Un type de token distinct et de courte durée pour « mot de passe
  vérifié mais pas encore le second facteur », volontairement non
  interchangeable avec un token de session complet
- RBAC par dépôt, vérifié sur chaque route — pas seulement masqué dans
  l'interface
- Journal d'audit et journal des événements de sécurité pour revue admin
- Validation par signature de fichier (magic bytes) sur les assets
  téléversés (logo/favicon de marque), sans jamais faire confiance au
  `Content-Type` fourni par le client

Vous avez trouvé une faille de sécurité ? Merci de la signaler en privé
plutôt que d'ouvrir une issue publique.

## Référence API — Authentification

- **`POST /api/auth/login`** — connecte l'utilisateur avec ses identifiants (nom d'utilisateur + mot de passe), retourne une réponse d'inscription à MFA si la connexion réussit.
- **`POST /api/auth/register`** — auto-inscrit un nouveau compte dans l'organisation publique (désactivée — 400 — sur tout autre sous-domaine d'organisation) ; retourne la même réponse d'inscription à MFA que login.

## Comparaison avec les alternatives

Hangar n'est pas la seule option pour héberger un registre npm et/ou
Docker. Voici où il se situe face à trois références du secteur — sur le
périmètre fonctionnel et le coût de licence, pas sur des chiffres de
performance : aucun benchmark comparatif n'a été mené entre ces quatre
outils, et il serait malhonnête d'en inventer.

| | **Hangar** | Nexus Repository (Community Edition) | Harbor | JFrog Artifactory |
|---|---|---|---|---|
| npm | ✅ | ✅ | ❌ | Payant (Pro) uniquement |
| Docker / OCI | ✅ | ✅ | ✅ | Payant (Pro) uniquement |
| Autres formats (Maven, PyPI, NuGet, Cargo, Helm…) | ❌ *(feuille de route)* | ✅ 20+ formats | OCI uniquement (Helm, SBOM, OPA…) | ✅ 60+ formats *(Pro)* |
| MFA | **Obligatoire**, natif (TOTP/passkey) | Optionnel, SSO en Pro | Optionnel | Optionnel, SSO en Pro |
| LDAP/OIDC | ✅ natif | Pro | ❌ | Pro |
| SAML | ❌ *(feuille de route)* | Pro | ❌ | Pro |
| Scan de vulnérabilités intégré | ✅ Trivy, natif | Produit séparé (Sonatype Lifecycle) | ✅ Trivy, natif | Payant (Xray) |
| Multi-tenant / projets isolés | ✅ organisations par sous-domaine | ✅ | ✅ | ✅ |
| Auto-hébergement gratuit | ✅ | ✅ (Community Edition) | ✅ (Apache 2.0, projet CNCF) | Java uniquement — Docker/npm exigent la version payante |

**Coût annuel estimé, auto-hébergé, hors infrastructure et exploitation**
(chiffres sourcés, pas de licence publique pour la plupart de ces
produits — voir les notes) :

- **Hangar** — gratuit, aucune licence.
- **Harbor** — gratuit, Apache 2.0, projet CNCF, aucune offre payante.
- **Nexus Repository Community Edition** — gratuit pour npm, Docker,
  Maven, PyPI et une quinzaine d'autres formats. La version Pro (SSO,
  haute disponibilité, réplication) n'a pas de tarif public ; des
  estimations tierces la situent autour de 120 $/utilisateur/an, ou
  50 000–150 000+ $/an packagée avec la plateforme Sonatype
  complète[^nexus-pricing].
- **JFrog Artifactory** — la version open-source (Apache 2.0) ne couvre
  que l'écosystème Java (Maven/Gradle/Ivy) : ni Docker ni npm. Pour les
  deux formats que Hangar couvre nativement et gratuitement, il faut la
  version Pro X, dont le tarif self-hosted annoncé démarre à
  27 000 $/an pour un serveur[^jfrog-pricing], et grimpe largement
  au-delà en configuration entreprise.

[^nexus-pricing]: [Sonatype Nexus Repository Pricing Guide — CloudRepo](https://www.cloudrepo.io/articles/sonatype-nexus-repository-pricing-guide)
[^jfrog-pricing]: [JFrog Artifactory Pricing Guide — CloudRepo](https://www.cloudrepo.io/articles/jfrog-artifactory-pricing-guide)

**Configuration matérielle recommandée** (chiffres tirés de la
documentation officielle de chaque produit, pas d'un test comparatif) :

| | **Hangar**[^hangar-bench] | Nexus Repository (Community Edition) | Harbor | JFrog Artifactory (Pro X, self-hosted) |
|---|---|---|---|---|
| CPU minimum | 0,5 cœur | 2 cœurs (profil « Small »)[^nexus-sysreq] | 2 cœurs[^harbor-prereqs] | 4 cœurs, jusqu'à 20 clients actifs[^jfrog-sizing] |
| CPU recommandé | 1 cœur | 4 à 8 cœurs selon le profil[^nexus-sysreq] | 4 cœurs[^harbor-prereqs] | 6 à 8 cœurs, jusqu'à 200 clients actifs[^jfrog-sizing] |
| RAM minimum | 128 Mo | 8 Go[^nexus-sysreq] | 4 Go[^harbor-prereqs] | 6 Go, jusqu'à 20 clients actifs[^jfrog-sizing] |
| RAM recommandée | 256 Mo | 8 à 32 Go selon le profil[^nexus-sysreq] | 8 Go[^harbor-prereqs] | 12 à 18 Go, jusqu'à 200 clients actifs[^jfrog-sizing] |
| Disque | non mesuré | ≥ 4 Go libres en permanence (sinon bascule en lecture seule) ; 500 Go+ courants avec Docker/Maven[^nexus-sysreq] | 40 Go minimum, 160 Go recommandé[^harbor-prereqs] | non chiffré dans la doc générale ; SSD conseillé[^jfrog-sysreq] |
| Base de données | PostgreSQL, obligatoire | H2 embarqué en évaluation, PostgreSQL recommandé en production[^nexus-sysreq] | PostgreSQL embarqué dans le bundle d'installation | PostgreSQL externe, obligatoire en production[^jfrog-sysreq] |
| Runtime | Binaire Rust natif, sans JVM | JVM, Java 21 requis[^nexus-sysreq] | Go, plusieurs conteneurs, pas de JVM | JVM, JDK 21 embarqué[^jfrog-sysreq] |

[^hangar-bench]: Mesuré, pas documenté : conteneur `hangar-api` limité via
    `docker run --cpus`/`--memory` (cgroup v2), face à 15-20 clients
    simulés (npm install/publish + docker pull/push, majoritairement en
    lecture) pendant 2-3 minutes. RAM et CPU lus directement dans
    `/sys/fs/cgroup/memory.current` et `cpu.stat` du conteneur, pas
    estimés. « Minimum » = 0,5 cœur / 128 Mo : la charge passe sans
    échec applicatif, mais avec un throttling CPU marqué (~68 % du temps
    d'exécution throttlé) et la RAM au ras du plafond. « Recommandé » =
    1 cœur / 256 Mo : 2185 requêtes, 2 échecs, throttling résiduel
    (~3 % du temps), RAM avec marge (pic à 92 Mo). Mesuré sur une
    machine de développement (pas un serveur dédié), donc pas
    directement comparable à la méthodologie des trois autres éditeurs,
    qui documentent des profils de dimensionnement pour des déploiements
    de production sur du matériel dédié.
[^nexus-sysreq]: [Sonatype Nexus Repository System Requirements](https://help.sonatype.com/en/sonatype-nexus-repository-system-requirements.html)
[^harbor-prereqs]: [Harbor Installation Prerequisites](https://goharbor.io/docs/2.13.0/install-config/installation-prereqs/)
[^jfrog-sizing]: [JFrog Hardware Sizing Matrix](https://docs.jfrog.com/installation/docs/hardware-sizing-matrix)
[^jfrog-sysreq]: [JFrog General System Requirements](https://docs.jfrog.com/installation/docs/general-system-requirements)

### Passage à l'échelle

Toujours mesuré, pas documenté : le tableau ci-dessus vient d'une charge
modeste (15-20 clients). Pour voir comment Hangar encaisse davantage de
concurrence, même conteneur (4 cœurs / 2 Go), mais cette fois piloté par
un générateur de charge HTTP asynchrone (Python/aiohttp) plutôt que de
vrais processus CLI npm/docker par client — ça permet de monter à 100 et
200 clients simultanés sans multiplier les processus lourds côté machine
de test[^hangar-scale] :

| Clients simultanés | Débit | Échecs | p95 (npm install) | CPU moyen | RAM (pic) |
|---|---|---|---|---|---|
| 20 | ~490 req/s | 0 | 90 ms | 108 % (de 4 cœurs) | 549 Mo |
| 100 | ~476 req/s | 0 | 360 ms | 108 % | 568 Mo |
| 200 | ~268 req/s | 0 | 1 781 ms | 81 % | 527 Mo |

Zéro échec applicatif à chaque palier, y compris à 200 clients : Hangar
ralentit sous forte charge mais ne casse pas. Point moins flatteur, dit
tel quel : le débit **baisse** entre 100 et 200 clients (476 → 268 req/s)
alors que le CPU utilisé baisse aussi (108 % → 81 %) — signe d'un goulot
d'étranglement qui n'est pas le manque de cœurs bruts (pool de connexions
PostgreSQL ou contention sur l'event-loop async, sans doute, mais non
investigué). Un seul run par palier, sur une machine de développement :
à prendre comme un ordre de grandeur, pas une garantie de capacité.

**Plus de CPU, plus de débit** — à 100 clients toujours, doubler
l'allocation CPU fait clairement bouger le débit soutenu :

| Config | Débit à 100 clients | Throttling CPU |
|---|---|---|
| 4 cœurs / 2 Go | ~476 req/s | marqué |
| 8 cœurs / 2 Go | ~690 req/s | léger |

Pas de ligne « RAM recommandée pour 100 clients » ici, volontairement :
avec un client qui tape sans aucune limite de débit, la RAM observée
grimpe avec la **durée du test** (backlog de requêtes en attente qui
s'accumule), pas avec une consommation stable par client — sur 15 s elle
plafonnait à 1,2 Go, sur 60 s elle a rempli les 4 Go alloués. Un chiffre
RAM fiable demanderait un client de charge avec un débit plafonné
(requêtes/seconde réaliste plutôt que « à fond »), ce qui n'a pas été
fait.

[^hangar-scale]: Générateur de charge : `aiohttp` en Python, appels HTTP
    directs sur les mêmes endpoints qu'un vrai client (métadonnées +
    tarball npm, jeton + manifeste + blob Docker), sans passer par les
    CLI `npm`/`docker`. Mix identique à la note précédente (majoritairement
    lecture). CPU/RAM lus dans les mêmes compteurs cgroup que le tableau
    ci-dessus.

**Ce que ces deux tableaux ne disent pas** : aucune mesure comparative
n'a été faite face à Nexus, Harbor ou Artifactory — les chiffres ci-dessus
ne concernent que Hangar. Nexus et Harbor sont par ailleurs des projets
matures, déployés à grande échelle depuis des années, avec des
fonctionnalités que Hangar n'a pas encore (voir la
[feuille de route](#feuille-de-route)) : SAML, haute disponibilité,
davantage de formats de paquets.

## Feuille de route

Hangar est un projet actif, pas un produit figé : quotas, rétention, scan
de sécurité intégré (Trivy + npm audit), marque personnalisable et MFA
obligatoire sont déjà natifs, et la liste ci-dessous est celle des chantiers
qu'on a vraiment envie de mener ensuite — par ordre de priorité
approximatif.

**Solidifier les fondations**
- [ ] SAML — LDAP/Active Directory et OIDC sont déjà supportés, SAML pas
      encore
- [ ] Davantage de formats de paquets : Maven/Gradle, PyPI, NuGet, Cargo,
      Go modules, Helm charts, dépôts génériques/raw — `hangar-npm`/
      `hangar-docker` montrent déjà le patron d'adaptateur à suivre
- [ ] Backend de stockage objet (compatible S3) derrière
      `StorageBackendPort`, pour débloquer les déploiements multi-réplicas
      (aujourd'hui : un seul volume fichier, une seule réplique)
- [ ] Haute disponibilité / clustering, réplication géographique
- [ ] Signature/provenance des paquets (Sigstore, npm provenance)

**Voir plus grand : un registre ouvert**
- [ ] Espaces de noms par utilisateur au sein d'une organisation (scopes
      façon npm `@user/...`), distincts du modèle actuel où les dépôts
      appartiennent à l'organisation
- [ ] Accès en lecture public, non authentifié, pour les paquets publics
- [ ] Limitation de débit et prévention des abus pour le trafic anonyme
- [ ] Pages de recherche et de découverte de paquets publiques
- [ ] Distribution d'artefacts mondiale via CDN

## Licence

Aucun fichier de licence n'est actuellement inclus dans ce dépôt —
considérez le code source comme tous droits réservés jusqu'à l'ajout
d'une licence.
