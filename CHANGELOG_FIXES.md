# Correctifs r3con 4.3.0 upgraded

## 4.3.0 — Corrections de bugs et dette technique

Audit systématique du code (`pyflakes`, vérification AST, revue manuelle) pour éliminer bugs silencieux et code mort.

**Bugs fonctionnels corrigés :**
- `r3con_core.py` : `analyze_binary_dynamic()` et 4 méthodes associées (`dynamic_crash_analysis`, `dynamic_find_offset`, `dynamic_generate_exploit`, `dynamic_gdb_script`) étaient définies deux fois. La seconde définition écrasait silencieusement la première (comportement normal de Python), qui était pourtant plus complète : `binary_info`, `security_score` et `rop_analysis` manquaient du résultat retourné par la version active. La duplication a été supprimée, la version complète est conservée.
- `modules/audit/static_analyzer.py` : `_check_double_free()` était dupliquée à l'identique sous le mauvais en-tête de section (copier-coller). Doublon supprimé.
- `modules/integration/external_tools.py` (`AFLWrapper.generate_harness`) : le nom de fonction cible (`target_func`) fourni par l'appelant était ignoré — le harnais AFL++ généré appelait toujours littéralement `target_function(data, size)` au lieu du vrai nom de fonction. Corrigé.
- `modules/integration/external_tools.py` (`Radare2Wrapper._r2`, `GDBWrapper._gdb`) : un script de commandes correctement formé était construit puis jamais utilisé ; l'appel réel repassait par une concaténation `"; ".join(...)` fragile en argument unique, qui casse si une commande contient un `;` littéral. `_r2` utilise maintenant stdin, `_gdb` utilise des flags `-ex` séparés par commande.

**Nettoyage de code mort (sans impact fonctionnel) :**
- Variable `names` jamais utilisée dans `modules/binary/rop_gadgets.py`.
- Variable `nano` (résolution PCAP) jamais exploitée dans `modules/network/protocol_analyzer.py`, renommée `_nano` pour signaler l'intention.
- Une quinzaine de f-strings sans interpolation (`f"texte fixe"`) simplifiées en chaînes normales dans `r3con_ci.py`, `r3con_core.py`, `core/report_gen.py`, `layers/layer3_intelligence.py`, `modules/dynamic/gdb_cli.py`, `modules/performance/batch_pipeline.py`, `modules/integration/external_tools.py`.

**Validation :** compilation Python de l'ensemble du dépôt réussie, suite pytest inchangée (12 passed, 1 skipped), smoke tests manuels sur `analyze_binary_dynamic`, `AFLWrapper.generate_harness` et `Radare2Wrapper._r2` réussis.

Numéro de version unifié à `4.3.0` dans tous les composants (CLI, core, config, rapports, documentation).

## Corrections appliquées

La version active a été uniformisée à `4.3.0` dans les composants principaux, les rapports, la configuration et la documentation de démarrage. Les références de dépôt et d’auteur laissées comme placeholders ont été retirées ou remplacées par des valeurs génériques sûres.

Le moteur IA ne sélectionne plus automatiquement un endpoint OpenAI-compatible présent dans l’environnement. L’activation d’un provider distant doit désormais être explicite avec `R3CON_AI_PROVIDER`, tandis que le mode local reste le comportement par défaut. Les clients OpenAI-compatible disposent également d’un délai maximal de 20 secondes.

Le cache incrémental expose maintenant `last_error` lorsqu’un chargement, une sauvegarde ou un hash échoue, au lieu d’ignorer silencieusement toutes les erreurs.

Les consultations NVD renvoient désormais un statut `error` et le détail de l’erreur lorsque le service est inaccessible, limité ou fournit une réponse invalide. Le fonctionnement hors ligne reste préservé.

Les artefacts de test et de compilation Python ont été exclus de la livraison finale.

## Validation

- Compilation Python : réussie.
- Tests autonomes : `50 passed, 0 failed`.
- Suite pytest : `7 passed, 1 skipped`.
- Smoke test CLI : version, audit source, strings binaires, analyse firmware et orchestration : réussis.
- Construction du wheel : réussie.


## 4.3.0 — Correctifs de cohérence

- Unification du call graph sur l’analyse interprocédurale AST-first.
- Fallback YARA explicitement nommé et suppression des doublons.
- CVE matching marqué comme heuristique avec confiance et disclaimer.
- Ajout d’une consultation OSV optionnelle avec provenance.
- Suppression de la copie `build/` obsolète.
- Ajout de tests de non-régression sans pytest.
