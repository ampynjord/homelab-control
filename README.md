# C2C

Centre de contrôle personnel pour un homelab, écrit en Rust avec une application de bureau Tauri 2. Il pilote et supervise des machines à travers un réseau privé (Tailscale) : état, réveil, affichage, streaming Sunshine/Moonlight, santé et journal d'audit.

## Principes

- **Tout passe par le réseau privé** : aucun service exposé sur Internet.
- **Aucun secret dans le code ni dans la configuration** : uniquement des références 1Password (`op://coffre/élément/champ`).
- **Droits minimaux** : chaque commande a un niveau de risque (lecture, courant, destructif). Les actions destructives demandent une confirmation explicite.
- **Une seule source de vérité** : la CLI et l'interface utilisent le même registre de commandes, et un test de parité échoue si elles divergent.
- **Agent authentifié** : requêtes signées Ed25519 par la clé privée de chaque appareil (gardée dans son propre 1Password), réponses signées par l'agent, anti-rejeu.

## Organisation

| Dossier | Rôle |
| --- | --- |
| `crates/c2c-core` | logique pure et testable (protocole, audit, affichage, santé, mises à jour signées) |
| `crates/c2c-api` | registre de commandes partagé par la CLI et l'interface |
| `crates/c2c-cli` | interface en ligne de commande |
| `crates/c2c-windows` | accès aux fonctions Windows (écrans, sessions) |
| `app/` | application de bureau (Tauri 2 + TypeScript) |
| `scripts/` | scripts d'installation Windows (agent, surveillance, pare-feu, mise à jour) |
| `examples/` | configuration d'exemple |

## Démarrage

```
cargo test
cargo run -p c2c-cli -- --config examples/c2c.example.toml status
cargo run -p c2c-cli -- --config examples/c2c.example.toml wake pc-fixe      # simulation
```

Tout effet réel exige `--execute`. Copier `examples/c2c.example.toml` en `c2c.toml` (ignoré par git) et l'adapter.

L'application de bureau se construit dans `app/` (`npm ci`, puis `npx tauri build`) avec la toolchain Rust MSVC sous Windows.

## Releases

Les exécutables sont construits par la CI à chaque tag `vX.Y.Z`, avec leur empreinte SHA-256.
