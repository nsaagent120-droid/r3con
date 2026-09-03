# Analyse réseau live passive dans r3con

r3con propose maintenant `network live`, un mode de capture **passif et borné** basé sur TShark. Il observe les paquets visibles sur une interface locale, agrège les flux, compte les protocoles et extrait les noms DNS, hôtes HTTP et SNI TLS observés. Il ne réalise ni scan, ni injection, ni envoi de payload.

## Utilisation rapide

```bash
# Capture locale pendant 30 secondes sur l’interface Linux "any"
r3con network live

# Capture courte sur loopback
r3con network live --interface lo --duration 10 --max-packets 5000

# Filtrer les paquets affichés par TShark
r3con network live --interface eth0 --duration 60 --filter 'dns or tcp'

# Écrire un résultat exploitable par un script
r3con network live --interface lo --duration 15 \
  --json-output live_capture.json
```

Le mode JSON contient le statut, l’interface, la durée effective, le nombre de paquets, le volume d’octets, les protocoles, les 500 flux les plus volumineux et les IOC observés dans les catégories `dns`, `http_hosts` et `tls_sni`.

## Paramètres

| Option | Valeur par défaut | Fonction |
|---|---:|---|
| `--interface` | `any` | Interface locale à écouter; `any` est généralement disponible sous Linux |
| `--duration` | `30` | Durée maximale en secondes, limitée à 3600 |
| `--max-packets` | `10000` | Nombre maximal de paquets traités, limité à 1 000 000 |
| `--filter` | aucun | Filtre d’affichage TShark, par exemple `dns or tcp` |
| `--json-output` | aucun | Fichier JSON agrégé au lieu du résumé terminal |

## Prérequis et permissions

TShark doit être installé et l’utilisateur doit avoir le droit de capturer sur l’interface choisie. Si la capture échoue, utilisez une interface précise comme `lo` ou `eth0`, vérifiez `tshark -D` et configurez les permissions de capture de votre distribution. Le mode ne tente pas d’élever ses privilèges automatiquement.

## Laboratoire et sécurité

Pour observer un binaire ou un firmware, utilisez une machine de laboratoire isolée, un namespace réseau, une interface virtuelle ou un réseau simulé. Ne lancez pas un échantillon inconnu sur une interface connectée à Internet. `network live` observe le trafic présent; il ne garantit pas que l’application observée soit la seule source de trafic de l’interface. Pour cette raison, les résultats doivent être corrélés avec les timestamps, les flux, les journaux du processus et les captures avant/après.

Le filtre `--filter` est transmis à TShark comme une valeur unique; il ne doit contenir que des expressions de filtre que vous comprenez et êtes autorisé à utiliser. Les sorties live peuvent contenir des adresses, noms de domaine ou autres données sensibles : protégez les fichiers JSON générés.

## Limites actuelles

Le module extrait les métadonnées exposées par TShark mais ne déchiffre pas TLS, ne reconstruit pas encore une machine à états complète de protocole et ne relie pas automatiquement un paquet à un PID. Une évolution ultérieure pourra ajouter une corrélation temporelle avec les journaux de processus, une reconstruction de conversations TCP et un mode lab avec snapshots filesystem, tout en conservant le caractère passif de la capture.
