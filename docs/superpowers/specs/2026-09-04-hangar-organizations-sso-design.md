# Hangar — Organisations, sous-domaines et identité d'entreprise (design)

## Contexte

Deux lignes de la feuille de route fusionnées en un seul chantier, à la demande explicite de
l'utilisateur : « Organisations multi-tenant » (aujourd'hui : un seul admin global, aucune
notion de tenant) et « Identité d'entreprise : LDAP/SAML/OIDC » (aujourd'hui : uniquement des
comptes locaux + TOTP/passkey obligatoire).

Motivation : envisager un Hangar hébergé publiquement (SaaS), pas seulement auto-hébergé. Ça
change la nature du produit — d'un outil mono-tenant pour une seule équipe à une plateforme
multi-tenant où chaque organisation cliente doit être **strictement isolée** des autres, tout en
gardant l'auto-hébergement mono-organisation comme cas d'usage également supporté (avec le même
modèle de routage, sans branche de code séparée).

Toutes les décisions de ce document ont été validées avec l'utilisateur au fil d'une session de
brainstorming ; aucune n'est une supposition de ma part.

## Objectif

- Introduire une entité **Organisation**, avec une organisation permanente `public` en
  inscription libre (façon npmjs.com), et des organisations d'entreprise créées par le
  super-admin.
- Router chaque organisation sur son propre sous-domaine (`<slug>.hangar.example` →
  l'organisation ; domaine racine/`www` → `public`), DNS wildcard obligatoire partout, y compris
  en auto-hébergement mono-organisation.
- Scoper à l'organisation : dépôts (npm + Docker), marque (logo/favicon), appartenance des
  utilisateurs.
- Isolation stricte entre organisations : une URL de dépôt/image qui fuite ne doit être
  exploitable par personne en dehors de l'organisation propriétaire, même authentifié ailleurs.
- Permettre à chaque organisation de brancher son propre fournisseur d'identité (LDAP,
  SAML, ou OIDC — un seul actif à la fois), avec provisioning automatique des comptes membres à
  la première connexion.
- Garder le rôle admin d'organisation strictement local (jamais délégué à un IdP externe), comme
  compte de secours.

## Modèle de données (vue d'ensemble)

Nouvelle table `organizations` (CRUD classique, pas d'event sourcing — même famille que
`users`/`system_settings`, pas `package_repository_projections`/`permission_projections` qui ont
un vrai besoin d'historique) :

```sql
CREATE TABLE organizations (
    id UUID PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,              -- sous-domaine : <slug>.hangar.example
    display_name TEXT NOT NULL,
    is_public BOOLEAN NOT NULL DEFAULT false, -- true uniquement pour l'organisation système `public`
    identity_provider JSONB,                -- NULL = comptes locaux uniquement (voir plus bas)
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Une seule organisation avec is_public = true, appliqué au niveau applicatif
-- (contrainte partielle possible : CREATE UNIQUE INDEX ... WHERE is_public)
```

Tables existantes modifiées :

```sql
ALTER TABLE users ADD COLUMN organization_id UUID NOT NULL REFERENCES organizations(id);
ALTER TABLE users ADD COLUMN is_organization_admin BOOLEAN NOT NULL DEFAULT false;
-- is_super_admin existe déjà, inchangé — global, indépendant de organization_id

ALTER TABLE package_repository_projections ADD COLUMN organization_id UUID NOT NULL REFERENCES organizations(id);
-- l'unicité du nom de dépôt passe de globale à (organization_id, name)
DROP INDEX IF EXISTS package_repository_projections_name_key; -- nom exact à vérifier au moment de l'implémentation
CREATE UNIQUE INDEX package_repository_org_name ON package_repository_projections(organization_id, name);

-- branding_settings (ou table équivalente) : ajout organization_id, la ligne `public`
-- porte le branding par défaut actuel de Hangar
ALTER TABLE branding_settings ADD COLUMN organization_id UUID NOT NULL REFERENCES organizations(id);
```

`hangar-domain` : nouveau module `organization.rs`.

```rust
pub struct Organization {
    pub id: Uuid,
    pub slug: String,           // même règles de parsing que Username : alphanumérique + tiret
    pub display_name: String,
    pub is_public: bool,
    pub identity_provider: Option<IdentityProviderConfig>,
    pub created_at: DateTime<Utc>,
}

pub enum IdentityProviderConfig {
    Ldap(LdapConfig),
    Saml(SamlConfig),
    Oidc(OidcConfig),
}

pub struct LdapConfig {
    pub server_url: String,       // ldaps://...
    pub bind_dn: String,
    pub bind_password: String,    // chiffré au repos, comme les identifiants de proxy remote existants
    pub user_search_base: String,
    pub user_search_filter: String, // ex. "(uid={username})"
    pub email_attribute: String,
}

pub struct SamlConfig {
    pub idp_entity_id: String,
    pub idp_sso_url: String,
    pub idp_certificate_pem: String,
}

pub struct OidcConfig {
    pub issuer_url: String,       // découverte via /.well-known/openid-configuration
    pub client_id: String,
    pub client_secret: String,    // chiffré au repos
}

#[async_trait]
pub trait OrganizationRepositoryPort: Send + Sync {
    async fn create(&self, org: &Organization) -> Result<(), DomainError>;
    async fn find_by_id(&self, id: Uuid) -> Result<Option<Organization>, DomainError>;
    async fn find_by_slug(&self, slug: &str) -> Result<Option<Organization>, DomainError>;
    async fn find_public(&self) -> Result<Organization, DomainError>; // toujours exactement une ligne
    async fn set_identity_provider(&self, id: Uuid, config: Option<IdentityProviderConfig>) -> Result<(), DomainError>;
}
```

## Rôles et permissions

Trois niveaux, du plus large au plus étroit :

1. **Super-admin** (`User.is_super_admin`, existe déjà) — global, toutes organisations y compris
   `public`. Toujours un compte local, jamais soumis au SSO d'une organisation.
2. **Admin d'organisation** (`User.is_organization_admin`, nouveau) — gère sa propre organisation
   uniquement (membres, marque, config SSO, dépôts). **Toujours un compte local** — un compte
   provisionné via SSO ne peut jamais porter ce rôle (voir section SSO). C'est le compte de
   secours si l'IdP de l'organisation tombe en panne.
3. **Rôle par dépôt** (`Role::Read/Write/Admin`, existe déjà, `permission_projections`) —
   inchangé dans sa mécanique, mais désormais implicitement scopé : un `repository_id` n'existe
   que dans une seule organisation, donc le rôle l'est aussi de fait.

`AuthUser` (middleware `hangar-api/src/auth_middleware.rs`) gagne deux champs :
`organization_id: Uuid` et `is_organization_admin: bool`, chargés depuis `users` comme
`is_super_admin` l'est déjà aujourd'hui.

## Résolution de l'organisation par sous-domaine

Nouveau middleware Axum, exécuté avant toute route dépendant d'une organisation (dépôts, marque,
SSO, admin d'organisation) :

```rust
pub struct ResolvedOrganization(pub Organization);

impl FromRequestParts<AppState> for ResolvedOrganization {
    // lit le header Host, retire le HANGAR_BASE_DOMAIN configuré (ex. "hangar.example")
    // - label restant vide ou "www" → organization.find_public()
    // - sinon → organization.find_by_slug(label), 404 si absent
}
```

Nouvelle variable d'environnement `HANGAR_BASE_DOMAIN` (obligatoire dès que ce chantier est
livré, y compris en auto-hébergement mono-organisation — pas de mode de repli sans
sous-domaine, décision explicite pour garder un seul modèle de routage). Le déploiement local
(`scripts/dev.sh`, tests) utilise un domaine de test type `hangar.localhost`, qui résout déjà
tous ses sous-domaines vers `127.0.0.1` nativement sur la plupart des systèmes — à vérifier au
moment de l'implémentation, sinon documenter l'entrée `/etc/hosts` nécessaire.

Les URLs de dépôts ne changent pas de forme (`/npm/<dépôt>/<paquet>`,
`/v2/<dépôt>/<image>` restent à un seul segment) : c'est la *résolution* qui change, de
`find_by_name(name)` à `find_by_org_and_name(resolved_org.id, name)`.

## Isolation entre organisations (sécurité)

Trois vérifications indépendantes, dans cet ordre, sur toute route touchant un dépôt (npm ou
Docker) — même famille de garantie que le fix IDOR sur les blobs Docker (`28cd3ec` dans
l'historique du projet, avant le squash) :

1. **Portée de la requête** — le dépôt est cherché *uniquement* dans `ResolvedOrganization`
   (issue du sous-domaine). Un dépôt d'une autre organisation n'apparaît jamais dans le
   résultat de la requête SQL — ce n'est pas une vérification après coup, la ligne n'existe
   simplement pas dans cet espace de recherche. Une URL qui fuite échoue déjà ici avec un
   `curl` brut, sans même regarder l'authentification.
2. **Appartenance** — `AuthUser.organization_id == resolved_org.id`, sauf super-admin qui
   passe toujours. Un compte authentifié d'une autre organisation échoue ici, même avec un
   jeton API valide.
3. **Rôle par dépôt** — inchangé, `Role::Read/Write/Admin` comme aujourd'hui.

Réponse **404** (pas 403) dès l'étape 1 ou 2, pour ne pas confirmer l'existence d'une ressource
dans une organisation à laquelle le demandeur n'a pas accès — cohérent avec la position actuelle
du projet sur les messages d'erreur qui ne doivent pas fuiter d'information (cf. les messages
d'erreur de dépôt/utilisateur dupliqué déjà spécifiques mais pas verbeux ailleurs dans le code).

Tests obligatoires à l'implémentation (miroir direct des tests écrits pour le fix IDOR
Docker) : un dépôt de l'organisation A n'est ni lisible ni listable depuis le sous-domaine de
l'organisation B, avec un compte de l'organisation B authentifié.

## Marque par organisation

`BrandingPort` (aujourd'hui un singleton) prend `organization_id` en paramètre de chaque
méthode. L'organisation `public` porte le branding Hangar par défaut actuel
(`branding_defaults` dans `hangar-infrastructure`, inchangé). Le frontend résout la marque à
afficher *avant* authentification (page de connexion comprise) à partir du sous-domaine — la
résolution par `Host` fonctionne pour du contenu public, contrairement à un éventuel préfixe de
chemin qui aurait demandé une résolution différente pour la page de connexion elle-même.

## Inscription publique

Nouvelle route `POST /api/auth/register`, disponible uniquement quand `ResolvedOrganization`
est `public` (400 ailleurs — pas d'auto-inscription sur une organisation d'entreprise). Flux :
username/email/mot de passe → création du compte dans `public`, rôle membre simple → même
parcours d'enrôlement MFA obligatoire que l'inscription actuelle par invitation (aucune
exception : `public` n'a pas de SSO, donc pas de contournement du MFA local possible).

## SSO — modèle commun

Chaque organisation a zéro ou un `IdentityProviderConfig` actif (voir modèle de données).
Dès qu'il est configuré, l'authentification locale des **membres simples** de cette organisation
est désactivée — seul le compte admin d'organisation (toujours local) garde l'accès par mot de
passe + MFA. Décision explicite : pas de bascule "SSO avec secours local pour tout le monde" —
seul l'admin a ce filet, pour garder un modèle de sécurité simple à raisonner.

**Provisioning à la première connexion (JIT)** : un email inconnu de l'organisation, authentifié
avec succès par l'IdP, obtient un compte créé à la volée — rôle membre simple, **jamais admin**,
quel que soit ce que l'IdP renvoie comme attribut de groupe ou de rôle. C'est la règle qui
empêche une IdP mal configurée ou compromise d'escalader quelqu'un en admin Hangar. Option par
organisation, pour plus tard si besoin : restreindre le JIT provisioning aux emails
pré-invités (hors périmètre de la première implémentation, à garder en tête dans la conception
du port).

Nouveau port partagé pour le provisioning (appelé par les trois adaptateurs) :

```rust
pub struct ExternalIdentity {
    pub email: String,
    pub display_name: Option<String>,
}

// dans hangar-application : find-or-create un utilisateur membre (jamais admin)
// dans l'organisation donnée, à partir d'une ExternalIdentity confirmée par l'IdP,
// puis émet un jeton de session directement (pas de flux MFA-pending : l'IdP est la
// source de vérité pour l'authentification de ce compte)
pub struct ProvisionSsoUserUseCase { /* ... */ }
```

### SSO — LDAP

Pas de redirection, un bind côté serveur dans la même requête :

```rust
#[async_trait]
pub trait LdapAuthPort: Send + Sync {
    async fn authenticate(&self, config: &LdapConfig, username: &str, password: &str)
        -> Result<ExternalIdentity, DomainError>;
    // implémentation : bind avec bind_dn/bind_password → recherche avec user_search_filter
    // → bind avec le DN trouvé + password soumis → email_attribute extrait sur succès
}
```

Route : `POST /api/auth/sso/ldap` (org résolue par sous-domaine), body `{username, password}`,
même forme de réponse que `/api/auth/login` mais sans jamais passer par `mfa_setup_required`.

Bibliothèque recommandée : `ldap3` (crate Rust la plus utilisée pour ce protocole).

### SSO — SAML

Flux de redirection :

```rust
#[async_trait]
pub trait SamlAuthPort: Send + Sync {
    fn build_redirect(&self, config: &SamlConfig, acs_url: &str) -> String; // AuthnRequest signée→URL
    fn handle_assertion(&self, config: &SamlConfig, raw_saml_response: &str)
        -> Result<ExternalIdentity, DomainError>; // vérifie la signature contre idp_certificate_pem
}
```

Routes : `GET /api/auth/sso/saml/login` (redirection), `POST /api/auth/sso/saml/acs`
(callback IdP, `acs_url` = `https://<slug>.hangar.example/api/auth/sso/saml/acs`).

Bibliothèque recommandée : `samael` — ne pas réimplémenter la vérification de signature XML à
la main, trop de pièges cryptographiques classiques sur ce protocole (XML signature wrapping
notamment).

### SSO — OIDC

Flux "Authorization Code" standard :

```rust
#[async_trait]
pub trait OidcAuthPort: Send + Sync {
    async fn build_redirect(&self, config: &OidcConfig, callback_url: &str) -> Result<String, DomainError>;
    async fn handle_callback(&self, config: &OidcConfig, code: &str, callback_url: &str)
        -> Result<ExternalIdentity, DomainError>; // échange code→jetons, valide l'ID token, extrait email
}
```

Routes : `GET /api/auth/sso/oidc/login` (redirection), `GET /api/auth/sso/oidc/callback`.

Bibliothèque recommandée : `openidconnect` (gère la découverte, la validation de l'ID token, et
PKCE).

### Configuration SSO par une organisation

`PUT /api/organizations/:id/identity-provider` et `DELETE` (retour aux comptes locaux) —
réservé à l'admin de cette organisation ou au super-admin. Un seul fournisseur actif à la fois ;
changer de type remplace la config précédente (pas de migration automatique des comptes déjà
provisionnés par l'ancien fournisseur — ils gardent leur compte local créé à l'époque).

## Création et migration des organisations

**Création** : réservée au super-admin (`POST /api/organizations`, pas d'auto-création en
libre-service). Le super-admin désigne dans la foulée un premier admin local pour la nouvelle
organisation, par le mécanisme d'invitation déjà existant (`invitation.rs`), adapté pour
accepter `organization_id` + `is_organization_admin: true`.

**Données existantes** : au déploiement de ce chantier, tous les utilisateurs, dépôts et jetons
déjà en base sont rattachés à l'organisation `public` (créée par la migration elle-même, avec un
slug fixe, par exemple `public`). C'est la seule option qui ne suppose rien sur une organisation
d'entreprise particulière, et reste cohérente avec l'usage actuel du projet (développement, pas
encore de vrais clients d'entreprise).

## Ce que ce design ne couvre pas (hors périmètre explicite)

- Un utilisateur membre de plusieurs organisations (décision : un compte = une organisation).
- Auto-création d'organisation par un utilisateur quelconque (décision : super-admin
  uniquement).
- Restriction du JIT provisioning SSO aux emails pré-invités (mentionné comme extension future
  du port, non implémenté dans ce chantier).
- Domaines personnalisés par organisation au-delà du sous-domaine `<slug>.hangar.example`
  (viendrait naturellement plus tard sur le même modèle de résolution par `Host`, mais pas
  demandé ici).
- Facturation/quotas différenciés par organisation (le quota par dépôt existe déjà et continue
  de s'appliquer tel quel, org par org).

## Notes d'implémentation (crates touchées)

- `hangar-domain` : `organization.rs` (nouveau), `user.rs` (+`organization_id`,
  +`is_organization_admin`), `branding.rs` (`BrandingPort` prend `organization_id`),
  `package_repository.rs` (recherche par nom devient recherche par `(organization_id, name)`).
- `hangar-application` : `CreateOrganizationUseCase`, `SetIdentityProviderUseCase`,
  `ProvisionSsoUserUseCase`, `RegisterPublicUserUseCase`, `AuthenticateViaLdapUseCase`,
  `InitiateSamlLoginUseCase`/`CompleteSamlLoginUseCase`,
  `InitiateOidcLoginUseCase`/`CompleteOidcLoginUseCase` ; use cases existants touchant
  dépôts/marque/permissions adaptés pour prendre `organization_id` en paramètre.
- `hangar-infrastructure` : `postgres/organization_repository.rs` (nouveau), adaptateurs
  `ldap_auth.rs` (`ldap3`), `saml_auth.rs` (`samael`), `oidc_auth.rs` (`openidconnect`) ;
  migration SQL du modèle de données ci-dessus, ajoutée directement dans `0001_init.sql`
  (convention déjà en place pour ce projet : un seul script de migration consolidé, pas de
  chaîne historique).
- `hangar-api` : middleware `ResolvedOrganization`, `routes/organizations.rs` (nouveau),
  `routes/auth.rs` (+routes SSO, +inscription publique), routes dépôts/marque adaptées pour
  utiliser l'organisation résolue.
- `hangar-npm`/`hangar-docker` : la résolution du dépôt par nom devient une résolution par
  `(organisation résolue, nom)` — changement de signature sur le port de recherche, pas de
  changement de forme d'URL.
- Frontend Angular : résolution de marque par sous-domaine avant authentification, boutons de
  connexion SSO conditionnés à la config de l'organisation résolue, pages d'administration
  d'organisation (marque, SSO, membres) pour l'admin d'organisation, page de gestion des
  organisations pour le super-admin.

Étant donné la taille du périmètre, l'implémentation sera probablement séquencée en plusieurs
plans distincts (fondation organisations + sous-domaines + isolation, puis LDAP, puis SAML, puis
OIDC, puis inscription publique) plutôt qu'un seul plan monolithique — décision à prendre au
moment de la planification (`superpowers:writing-plans`), pas dans ce document de design.
