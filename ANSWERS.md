Date : Mercredi, le 9 Octobre 2024

Edité par : Yavo CHABEHOU

## 1. Prérequis

1. Comment s'appelle cette topology ?

Il s'agit d'une architecture client-serveur. Le serveur chat_server.py centralise les messages et les redistribue aux clients connectés (basic_gui.py).

2. Que remarquez vous dans les logs ? 

Les messages sont visibles en clair dans les logs du serveur, ce qui constitue un non respect de la confidentialité.

3. Pourquoi est-ce un problème et quel principe cela viole t-il ?

Le problème est que n'importe qui peut intercepter les messages et les lire, ce qui viole le principe de confidentialité.

4. Quelle solution la plus **simple** pouvez-vous mettre en place pour éviter cela ? Détaillez votre réponse.

La solution est de chiffrer les messages avant de les envoyer sur le réseau, et de les déchiffrer à la réception. 
Cela empêchera les personnes non autorisées de lire les messages, même si elles parviennent à les intercepter.


## 2. Chiffrement

1. Est ce que urandom est un bon choix pour de la cryptographie ? Pourquoi ?

    Oui, os.urandom est un bon choix pour la cryptographie. Il utilise une source d'aléatoire fournie par le système d'exploitation, qui est généralement considérée comme cryptographiquement sûre.  
    Contrairement à random.random qui utilise un algorithme déterministe, os.urandom  génère des nombres aléatoires à partir de sources d'entropie du système, comme les mouvements de la souris

2. Pourquoi utiliser ses primitives cryptographiques peut être dangereux ?

Utiliser des primitives cryptographiques peut être dangereux pour plusieurs raisons :

    - Choix d'algorithmes faibles ou obsolètes
    - Mauvaise implémentation
    - Manque d'authentification 

3. Pourquoi malgré le chiffrement un serveur malveillant peut il nous nuire encore ?

Parce que : 

    - Modification des messages : Le serveur pourrait modifier les messages chiffrés avant de les relayer aux autres clients. Même si le serveur ne peut pas lire le contenu des messages, il peut les altérer, ce qui pourrait entraîner des erreurs ou des comportements inattendus chez les clients.

    - Enregistrement des messages : Le serveur pourrait enregistrer les messages chiffrés et les déchiffrer plus tard s'il parvient à obtenir la clé de chiffrement.

4. Quelle propriété manque t-il ici ?

    Il manque l'intégrité. Le chiffrement assure la confidentialité, mais il ne garantit pas que les messages n'ont pas été modifiés pendant le transit. De plus, il ne permet pas de vérifier l'identité de l'expéditeur.



## Authenticated Symetric Encryption


1. Fernet présente un risque d'implémentation inférieur par rapport au chapitre précédent, car il adopte un schéma de chiffrement authentifié qui assure l'intégrité du message. De plus, la bibliothèque cryptography contribue à réduire les erreurs potentielles d'implémentation.

2. Cette attaque est désignée sous le terme de "rejeu".

3. Une méthode efficace pour prévenir les attaques de rejeu consiste à utiliser des numéros de séquence dans les messages,  garantissant ainsi l'unicité de chaque message.



## TTL


1. Aucune différence observable, la longueur du message reste inchangée.

2. Si l'on soustrait 45 secondes au temps d'émission, le message chiffré ne pourra pas être déchiffré, car son temps de réception sera jugé antérieur au temps d'émission, entraînant ainsi son expiration. Avec un TTL de 30 secondes, en soustrayant 45 secondes, le temps de réception sera décalé de 15 secondes avant l'émission, ce qui dépasse la durée de vie du message.

3. Oui, l'application d'un TTL s'avère efficace pour se protéger contre les attaques de rejeu.

4. Il est impératif de réduire le temps de sécurisation des messages dans la pratique, car en moins de 30 secondes, une machine peut initier une attaque de rejeu. De plus, la latence sur la connexion peut entraîner le traitement de messages valides comme invalides.