# Hangar — Gestion fine des organisations (design)

## Contexte

Le modèle multi-tenant existe déjà en base (`organizations`, `users.organization_id`,
`users.is_organization_admin`) et le backend expose déjà `POST /api/organizations`
(création) ainsi que `require_organization_admin` (super-admin OU org-admin de cette
organisation précise), déjà utilisé pour le branding et la configuration SSO/LDAP d'une
organisation. Mais deux trous empêchent toute utilisation réelle de ce modèle :

1. **Aucune UI ne permet de créer une organisation** — l'endpoint existe, `organizations-list`
   n'a jamais de bouton/modale pour l'appeler (contrairement à `users-list`/`repositories-list`
   qui en ont un).
2. **Aucune UI ne permet de gérer les utilisateurs d'une organisation.** Pire : le backend
   (`POST /api/users`) crée toujours l'utilisateur dans `resolved_org` — l'organisation résolue
   depuis le domaine sur lequel la requête arrive — jamais dans une organisation choisie
   explicitement. Un super-admin naviguant sur un seul domaine ne peut donc inviter des
   utilisateurs que dans l'organisation de CE domaine.
3. Conséquence du point 2 : la capacité déjà existante d'org-admin (branding/SSO) n'est
   accessible par AUCUNE route frontend — toutes les routes `/admin/*`, y compris
   `/admin/organizations/:id`, sont gardées par `adminGuard` (super-admin uniquement). Un
   org-admin qui n'est pas super-admin n'a strictement aucun moyen d'atteindre la page de sa
   propre organisation aujourd'hui.

## Objectif

- Depuis `/admin/organizations`, un super-admin peut créer une nouvelle organisation
  (slug + nom d'affichage).
- Depuis `/admin/organizations/:id`, on peut : lister les membres de cette organisation,
  en inviter un nouveau directement dans cette organisation (quel que soit le domaine
  actuellement utilisé), et promouvoir/rétrograder le statut d'administrateur
  d'organisation d'un membre existant.
- Cette page devient accessible à l'organisation-admin de CETTE organisation précise, pas
  seulement au super-admin — première route frontend à réellement exposer la capacité
  org-admin déjà présente côté backend.
- **Hors périmètre** : déplacer un utilisateur existant vers une autre organisation (non
  demandé) ; changer `is_super_admin` depuis cette page (reste exclusivement sur `/users`,
  seul terrain du super-admin global) ; onglets ou changement de layout sur
  `organization-detail` (une troisième carte suffit, cohérent avec l'existant).

## Backend

**`/api/me`** (`MeResponse`, `crates/hangar-api/src/routes/auth.rs`) : ajout de
`organization_id: Uuid` et `is_organization_admin: bool`, lus directement depuis
`AuthUser` (déjà porteur de ces deux champs). Nécessaire pour que le frontend sache si
l'utilisateur courant administre une organisation, et laquelle.

**`UserRepositoryPort`** (`crates/hangar-domain/src/user.rs`) : nouvelle méthode

```rust
async fn set_organization_admin(&self, id: Uuid, is_organization_admin: bool) -> Result<(), DomainError>;
```

Miroir de `set_super_admin`, mais sans variante "unless_last" : contrairement au
super-admin global, une organisation peut valablement se retrouver sans aucun org-admin
(le super-admin global reste toujours capable de la gérer). Implémentation Postgres dans
`crates/hangar-infrastructure/src/postgres/user_repository.rs` (`UPDATE users SET
is_organization_admin = $2 WHERE id = $1`) ; toutes les implémentations de test (fakes)
du trait dans `hangar-application/src/use_cases/*.rs` reçoivent la même méthode
(généralement `Ok(())` pour celles qui ne testent pas ce chemin), suivant exactement le
même schéma que l'ajout historique de `set_super_admin_unless_last`.

**Nouveau `SetOrganizationAdminUseCase`** (`crates/hangar-application/src/use_cases/user.rs`,
à côté de `SetSuperAdminUseCase`) : appelle simplement `users.set_organization_admin(id,
value)`.

**Trois nouvelles routes** sous `/api/organizations/:id/users`
(`crates/hangar-api/src/routes/organizations.rs`), toutes protégées par
`require_organization_admin(&user, id)` (déjà existant, déjà testé) :

- `GET /api/organizations/:id/users` — liste les membres de cette organisation. Implémentation :
  `state.users.list_all()` puis `.filter(|u| u.organization_id == id)`, exactement le
  même idiome que `search_users` dans `routes/users.rs` (pas de nouvelle méthode de port
  pour un filtrage en base — le volume d'utilisateurs d'un registre auto-hébergé ne le
  justifie pas). Réponse : liste de `{ id, username, email, is_organization_admin,
  invitation_pending }` (même forme que `UserResponse` existant, `is_organization_admin`
  en plus).
- `POST /api/organizations/:id/users` — invite un utilisateur dans l'organisation `:id`.
  Corps : `{ username, email, is_organization_admin }`. **Pas de champ `is_super_admin`
  dans ce DTO** — la route appelle `state.invite_user.execute(id, body.is_organization_admin,
  &body.username, &body.email, false)` : le `false` est câblé en dur, pas dérivé de la
  requête. Un org-admin ne peut donc pas obtenir super-admin par ce chemin même en
  forgeant la requête HTTP ; ce n'est pas qu'une case cachée côté UI.
- `PUT /api/organizations/:id/users/:user_id/organization-admin` — promeut/rétrograde.
  Corps : `{ is_organization_admin: bool }`. Vérifie d'abord que l'utilisateur ciblé
  appartient bien à l'organisation `:id` (`state.users.find_by_id(user_id)` puis
  comparaison ; 404 si absent ou si `organization_id != id`, même posture de
  confidentialité que `require_same_organization` — ne pas révéler qu'un utilisateur
  existe dans une autre organisation), puis appelle `SetOrganizationAdminUseCase`.

## Frontend

**`MeService`** (`frontend/src/app/shell/application/me.service.ts`) : deux signaux
supplémentaires, `organizationId` et `isOrganizationAdmin`, peuplés depuis la même
réponse `/api/me` déjà chargée (aucun appel réseau supplémentaire).

**Nouveau guard `organizationAdminGuard`** (`frontend/src/app/auth/organization-admin.guard.ts`,
miroir de `admin.guard.ts`) : remplace `adminGuard` uniquement sur la route
`admin/organizations/:id`. Autorise si `me.isSuperAdmin()`, ou si
`me.isOrganizationAdmin()` et que le paramètre de route `id` correspond à
`me.organizationId()` ; redirige vers `/repositories` sinon. La route `admin/organizations`
(la liste complète) reste sur `adminGuard` — seul le super-admin doit voir toutes les
organisations.

**Menu latéral** (`app-shell`) : nouveau lien "Mon organisation" vers
`/admin/organizations/${me.organizationId()}`, visible quand `me.isOrganizationAdmin()`
est vrai ET `me.isSuperAdmin()` est faux (un super-admin atteint déjà n'importe quelle
organisation via "Organisations").

**`organizations-list`** : bouton "Nouvelle organisation" (même emplacement que
"Nouvel utilisateur"/"Nouveau dépôt") ouvrant un nouveau `create-organization-modal`
(slug + nom d'affichage, validation similaire à `create-repository-modal`). Nouvelle
méthode `create(slug, displayName)` sur `OrganizationsService`/`OrganizationsPort`/
`HttpOrganizationsAdapter`, appelant `POST /api/organizations` (déjà implémenté
côté backend, aucun changement de contrat).

**Nouveau composant `app-organization-members`**
(`frontend/src/app/admin/organization-members/`, même esprit que `app-mfa-settings`/
`app-passkey-settings` : autonome, injecté dans une page hôte) :

- Un `gbt-table` des membres (colonnes : nom d'utilisateur, e-mail, badge "Administrateur"
  si `is_organization_admin`, statut d'invitation).
- Bouton "Inviter un membre" ouvrant un formulaire (nom d'utilisateur, e-mail, case à
  cocher "Administrateur de cette organisation" — **aucun champ super-admin**, cohérent
  avec le DTO backend qui ne l'accepte pas).
- Une action promouvoir/rétrograder par ligne (bouton bascule appelant le `PUT
  .../organization-admin`).

Nouvelle couche `domain`/`application`/`infrastructure` dédiée
(`organization-member.entity.ts`, `organization-members.port.ts`,
`organization-members.service.ts`, `http-organization-members.adapter.ts`), suivant
exactement le découpage déjà en place pour chaque autre ressource de l'application.

**`organization-detail.html`** : le nouveau composant est intégré comme troisième
`<gbt-card>` ("Membres"), enveloppée dans `.stack` comme les deux cartes existantes
("Informations", "Authentification") — pas d'onglets, cohérent avec le layout actuel de
la page.

## Tests

**Backend** — pour les trois nouvelles routes, réutilisation exacte des cas déjà
couverts par les tests existants de `require_organization_admin` :
super-admin autorisé sur n'importe quelle organisation ; org-admin de CETTE organisation
autorisé ; membre simple de cette organisation rejeté (403) ; org-admin d'une AUTRE
organisation rejeté (404, pas 403, cohérent avec `require_same_organization`). Plus,
spécifiquement : régression garantissant que le corps de la requête `POST .../users` ne
peut jamais produire un utilisateur `is_super_admin: true`, même si ce champ est ajouté
de force à la requête JSON ; 404 sur `PUT .../organization-admin` si `:user_id`
n'appartient pas à l'organisation `:id`.

**Frontend** — nouveau fichier de specs pour `organizationAdminGuard` (mêmes trois cas
que `admin.guard.spec.ts`, plus le cas "org-admin mais mauvaise organisation") ; specs
pour `create-organization-modal` et `app-organization-members` (rendu de la liste, flux
d'invitation, flux de promotion, cas d'erreur) suivant le patron `HttpTestingController`
déjà utilisé partout ailleurs ; extension de `organization-detail.spec.ts` (présence de
la carte Membres) et de `me.service.spec.ts`/`http-me.adapter.spec.ts` (nouveaux champs).
