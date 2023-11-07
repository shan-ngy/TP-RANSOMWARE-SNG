# TP2

## Q1 : Quelle est le nom de l'algorithme de chiffrement ? Est-il robuste et pourquoi ?

L'algorithme XOR, utilisé ici, est une forme de chiffrement symétrique, nécessitant une clé commune pour le chiffrement et le déchiffrement. Cela accélère le processus, mais présente des vulnérabilités : si la clé est plus courte que les données, elle est répétée, créant des schémas exploitables par un attaquant. Si une clé est utilisée pour chiffrer plusieurs messages, des techniques d'analyse de fréquence peuvent la compromettre. Enfin, si un attaquant connaît le texte clair et son équivalent chiffré, il peut déterminer la clé en effectuant une opération XOR inverse. 

## Q2 : Pourquoi ne pas hacher le sel et la clef directement ? Et avec un hmac ?

Il est déconseillé de hacher directement le sel et la clé avec un HMAC, car les fonctions de hachage sont rapides et vulnérables aux attaques par force brute. En revanche, PBKDF2 (Password-Based Key Derivation Function 2) est conçu spécifiquement pour dériver des clés à partir de données secrètes. Il ajoute un sel et utilise un grand nombre d'itérations pour renforcer la sécurité. Alors que le HMAC est principalement utilisé pour vérifier l'intégrité des données, PBKDF2 offre un niveau de sécurité supérieur en matière de dérivation de clé.

## Q3 : Pourquoi il est préférable de vérifier qu'un fichier token.bin n'est pas déjà présent ?
Il est préférable de vérifier si un fichier token.bin existe déjà pour éviter d'écraser un token existant, d'éviter de générer et d'envoyer des éléments cryptographiques inutiles, et d'économiser des ressources inutilement.

## Q4 : Comment vérifier que la clef la bonne ?

Pour vérifier que la clé est la bonne, il faut dériver la clé fournie avec le sel (salt) en utilisant la même fonction de dérivation que celle utilisée pour créer la clé initiale lors de la configuration initiale (donc ici PBKDF2HMAC).
