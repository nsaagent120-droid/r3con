"""
tests/test_all.py est un script autonome (`python tests/test_all.py`),
pas une suite pytest : il definit une fonction interne `test(n, c)` qui
entre en collision avec la convention de decouverte de pytest
(python_functions = "test*"), ce qui produisait une fausse erreur de
collection ("fixture 'c' not found") quand on lancait `pytest tests/`.
On l'exclut explicitement de la collection pytest plutot que de
renommer cette fonction utilisee dans des centaines d'appels a travers
le fichier.
"""
collect_ignore = ["test_all.py"]
