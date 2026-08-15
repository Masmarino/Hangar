# Hangar — Paramètres système et serveur mail par organisation (design)

## Contexte

Dernier volet de la décomposition « dashboard admin limité à son organisation » (Marque,
Jetons API, Historique + Sécurité et Métriques sont déjà livrés). `system_settings`
(tentatives de connexion, fenêtre de throttling, durée de session, inscription ouverte) et
`smtp_settings` (relais SMTP sortant) sont aujourd'hui des tables singleton
(`id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1)`) — une seule ligne pour toute
l'installation, sans colonne `organization_id`. Contrairement aux quatre volets
précédents, il ne s'agit pas d'un simple filtre à ajouter à une requête existante : cela
touche le chemin d'authentification (`LoginThrottle`, émission des JWT de session) et
l'envoi d'e-mail (invitations, réinitialisation de mot de passe, MFA, WebAuthn, e-mail de
test), qui sont aujourd'hui des mécanismes globaux, en partie purement en mémoire.

Deux fils sont volontairement traités ensemble ici parce qu'ils partagent le même
changement de schéma (singleton → une ligne par organisation) et le même mécanisme de
migration, même si leurs implications runtime sont très différentes :

- **SMTP** : la résolution "quels réglages utiliser" est mécanique une fois le port
  changé, car chaque appelant a ou peut obtenir un `organization_id`.
- **Paramètres système** : `LoginThrottle` vérifie le seuil *avant* de savoir si le nom
  d'utilisateur correspond à un compte réel, et la durée de session (`session_ttl_hours`)
  est aujourd'hui un atomique global lu à l'émission de chaque JWT. Les deux deviennent
  des valeurs résolues par organisation au moment de l'appel, plutôt que des réglages
  globaux appliqués une fois au démarrage.

## Objectif

- Un org-admin peut consulter et modifier, pour sa seule organisation : les réglages de
  throttling de connexion et de durée de session, l'activation de l'auto-inscription, et
  la configuration SMTP — mêmes formulaires que ceux du super-admin aujourd'hui.
- Une organisation sans SMTP configuré ne peut simplement pas envoyer d'e-mail pour ses
  membres (mêmes sémantiques qu'aujourd'hui à l'échelle de l'instance) — **aucun repli**
  implicite vers un SMTP "par défaut" d'une autre organisation.
- Une organisation sans ligne `system_settings` propre utilise des valeurs par défaut
  (mêmes valeurs que les constantes actuelles) plutôt qu'une absence de réglages — on ne
  peut pas raisonnablement laisser une organisation sans seuil de throttling ou sans durée
  de session.
- La ligne singleton existante de chacune des deux tables est reprise telle quelle par
  l'organisation `public` (id `00000000-0000-0000-0000-000000000001`) lors de la
  migration — continuité pour l'installation déjà configurée.
- **Hors périmètre** : tout mécanisme de repli SMTP inter-organisations ; rendre le
  throttling par IP de `/api/auth/register` attribuable à une organisation (il s'applique
  avant même de savoir si le nom d'utilisateur correspond à un compte, donc avant de
  connaître une organisation — reste sur les constantes globales actuelles
  `MAX_LOGIN_ATTEMPTS`/`LOGIN_ATTEMPT_WINDOW`, exactement comme les événements
  `LoginFailed` déjà exclus de l'historique organisationnel).

## Backend — schéma

```sql
ALTER TABLE system_settings DROP CONSTRAINT system_settings_pkey;
ALTER TABLE system_settings DROP COLUMN id;
ALTER TABLE system_settings ADD COLUMN organization_id UUID REFERENCES organizations(id);
UPDATE system_settings SET organization_id = '00000000-0000-0000-0000-000000000001';
ALTER TABLE system_settings ALTER COLUMN organization_id SET NOT NULL;
ALTER TABLE system_settings ADD PRIMARY KEY (organization_id);
```

Même transformation pour `smtp_settings`. Les deux tables passent de "au plus une ligne,
contrainte par CHECK" à "au plus une ligne par organisation, clé primaire naturelle" — pas
besoin de table de junction, `organization_id` devient directement la clé primaire.

## Backend — ports et implémentations Postgres

**`SystemSettingsPort`** (`crates/hangar-domain/src/system_settings.rs`) :

```rust
async fn get(&self, organization_id: Uuid) -> Result<SystemSettings, DomainError>;
async fn update(&self, organization_id: Uuid, settings: &SystemSettings) -> Result<(), DomainError>;
```

`get` ne devient pas `Option` : une organisation sans ligne reçoit
`SystemSettings::defaults()` (déjà existant), exactement le comportement actuel au
premier démarrage. Implémentation Postgres : `SELECT ... WHERE organization_id = $1`,
`INSERT ... ON CONFLICT (organization_id) DO UPDATE`.

**`SmtpSettingsPort`** (`crates/hangar-domain/src/email.rs`) : mêmes signatures, mais
`get` reste `Option<SmtpSettings>` — `None` veut dire non configuré, sémantique déjà
existante, désormais par organisation plutôt que pour l'instance entière.

**`EmailPort::send`** (`crates/hangar-domain/src/email.rs`) : gagne un paramètre
`organization_id: Uuid` en première position. `SmtpEmailSender::send`
(`crates/hangar-infrastructure/src/smtp_email_sender.rs`) l'utilise pour
`self.settings.get(organization_id)` — et, effet de bord bienvenu, pour
`self.branding.get(organization_id)` à la place du `PUBLIC_ORGANIZATION_ID` codé en dur
actuel (`TODO(organizations)` déjà présent dans ce fichier, avec la remarque explicite que
c'est un contournement temporaire). Sept sites d'appel à mettre à jour
(`crates/hangar-application/src/use_cases/{admin,invitation,mfa,user,webauthn,smtp}.rs`) —
chacun a déjà soit `user_id` (résolu en `organization_id` via
`self.users.find_by_id(user_id)`, déjà injecté dans chacun de ces use cases), soit
`organization_id` directement (création d'invitation).

## Backend — throttling de connexion

`LoginThrottle` (`crates/hangar-api/src/login_throttle.rs`) perd ses champs
`max_attempts`/`window_millis` et les méthodes `set_limits`/`with_limits` associées : il
redevient un pur traqueur de tentatives, sans notion de limite qui lui soit propre.

```rust
pub fn is_throttled(&self, key: &str, max_attempts: usize, window: Duration) -> bool;
pub fn record_failure(&self, key: &str, max_attempts: usize, window: Duration);
pub fn clear(&self, key: &str); // inchangé, une limite n'est pas nécessaire pour effacer
```

`POST /api/auth/login` (`crates/hangar-api/src/routes/auth.rs`) résout l'organisation
*avant* le contrôle de throttling, via `state.users.find_by_username(&body.username)` (déjà
disponible sur `UserRepositoryPort`) :

- utilisateur trouvé → `state.system_settings.get(user.organization_id).await` fournit
  `max_login_attempts`/`login_attempt_window_seconds` ;
- utilisateur introuvable → aucune organisation à résoudre, retombe sur les constantes
  globales actuelles (`MAX_LOGIN_ATTEMPTS`, `LOGIN_ATTEMPT_WINDOW`) — un nom d'utilisateur
  inventé est throttlé exactement comme aujourd'hui, sans fuite d'information sur son
  existence.

C'est le seul vrai changement de comportement de ce sous-projet : une lecture BDD
supplémentaire (indexée, sur `username UNIQUE`) sur le chemin de connexion, qui était
jusqu'ici entièrement en mémoire (commentaire de module à mettre à jour en conséquence).
`POST /api/auth/register`, dont la clé de throttling est une IP et non un nom
d'utilisateur, garde les constantes globales sans changement (hors périmètre, voir
ci-dessus).

## Backend — durée de session

`TokenIssuerPort::issue` (`crates/hangar-domain/src/user.rs`) gagne un paramètre
`ttl: chrono::Duration` :

```rust
fn issue(&self, user_id: Uuid, ttl: Duration) -> Result<String, DomainError>;
```

`JwtTokenIssuer` (`crates/hangar-infrastructure/src/jwt_token_issuer.rs`) perd son champ
`ttl_secs: AtomicI64` et `set_ttl` : `issue` utilise directement le `ttl` reçu. Chaque site
d'appel en production (8, tous hors tests — `routes/auth.rs` × 5 : connexion réussie,
vérification TOTP, vérification code de secours, connexion par clé d'accès, callback SSO ;
`use_cases/sso.rs` × 2 ; `use_cases/user.rs` × 1, activation de compte invité) résout
`state.system_settings.get(user.organization_id).await` puis passe
`Duration::hours(settings.session_ttl_hours as i64)`. Ce sont tous des chemins déjà
post-authentification (l'utilisateur est déjà résolu), donc aucune lecture BDD
supplémentaire n'est ajoutée par rapport à ce que ces handlers font déjà.

`apply_system_settings` et son unique appelant côté administration
(`crates/hangar-api/src/state.rs`, invoqué par `update_system_settings` dans
`routes/admin.rs`) disparaissent entièrement : il n'y a plus d'état global à pousser vers
`LoginThrottle`/`JwtTokenIssuer` après une modification, ces objets n'en détiennent plus.

## Backend — inscription ouverte

`registration_enabled` suit le même schéma per-org que le reste de `SystemSettings`. Le
handler `register` (`routes/auth.rs`) résout déjà `resolved_org.0.is_public` ; il résout en
plus `state.system_settings.get(resolved_org.0.id).await?.registration_enabled` et combine
les deux (comme aujourd'hui l'un implique déjà presque l'autre, mais les deux flags restent
indépendants — un organisation publique peut vouloir couper temporairement l'inscription
sans changer son statut public).

## Backend — routes admin

`GET/PUT /api/admin/settings` et `GET/PUT /api/admin/settings/smtp`
(`crates/hangar-api/src/routes/admin.rs`) : passage de `require_super_admin` à
`require_organization_admin(&user, target_organization_id)`, où
`target_organization_id` réutilise exactement le helper déjà écrit pour le branding
(`target_organization_id(&user, &resolved_org)` dans `routes/branding.rs` — super-admin
gère l'organisation résolue par le domaine, org-admin gère toujours la sienne quel que
soit le domaine). `POST /api/admin/settings/smtp/test` suit la même règle, et
`self.email.send(target_organization_id, ...)`.

## Frontend

Aucun nouveau composant : `system-settings` et `smtp-settings` (composants admin
existants) sont intégrés tels quels dans `organization-detail.html`, même schéma que
Marque/Jetons/Métriques — le scoping est entièrement porté par le backend, les composants
n'ont pas de notion d'organisation à leur passer puisque les endpoints qu'ils appellent
répondent déjà en fonction de l'appelant.

## Tests

**Backend** — nouveaux cas, en réutilisant le patron déjà établi pour Jetons/Historique/Métriques
(org-admin sur sa propre organisation ; org-admin d'une autre organisation rejeté ; membre
simple rejeté) :

- `system_settings`/`smtp_settings` : lecture et écriture par un org-admin scoped à sa
  seule organisation, sans effet sur une autre.
- Throttling : deux organisations avec des `max_login_attempts` différents ; un compte
  bloqué dans l'une ne l'est pas dans l'autre ; un nom d'utilisateur inexistant utilise
  les constantes globales.
- Durée de session : token émis avec le TTL de l'organisation de l'utilisateur, pas un
  TTL global.
- E-mail : un `EmailPort` fake enregistrant l'`organization_id` reçu, vérifié sur au
  moins un site d'appel (invitation) pour prouver que le bon paramètre est propagé de
  bout en bout.
- Migration : la ligne singleton existante se retrouve bien rattachée à l'organisation
  `public` après migration (test au niveau infrastructure, comme les tests de migration
  déjà existants dans `hangar-infrastructure`).

**Frontend** — extension d'`organization-detail.spec.ts` (présence des deux cartes),
suivant exactement le même patron que les quatre sous-projets précédents.
