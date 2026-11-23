## Detection 

Pour écrire les règles pouvant détecter les extractions des identifiants d’un utilisateur Windows, nous devons voir les
processus qui ont accès a la mémoire LSASS. Pour cela, nousl’ID10 de sysmon peut nous renseigner les valeurs importantes
pour nous permettre d’écrire notre règle pour la detection. Nous accédons au gestionnaire d’evenements Windows >
Windows security > security events





<img width="2048" height="1080" alt="image" src="https://github.com/user-attachments/assets/ca977740-4537-464c-ac4c-e61ef90b3db9" />


## -----------------------------------------------------------------------------------------------------------------------------------------------
Ainsi donc si nous pouvons voir dans les logs brutes de Windows les champs critiques qui nous indiquent qu’il y a eu
une possible attaque d’extraction d’identifiants Notre règle avec pour ID 110008



<img width="1884" height="558" alt="image" src="https://github.com/user-attachments/assets/1299e74a-51ae-46c6-9e6c-a531bcbc26d5" />


## Response 

Nous allons ici utiliser le module « Active-Response » de Wazuh qui vient par défaut. Pour répondre a l’attaque Carentiels accès, Nous allons :
Dans un premier temps déconnecter la session de l’utilisateur compromis, cette action sera exécuter sur le poste infecter via un script que nous
avons écrit permettant de déconnecter la session au déclenchement de l’active-response Puis un autre script va s’exécuter depuis le Domain Contrôler pour désactiver le
compte afin d’éviter que les identifiants volées ne soient réutiliser.

Script pour la déconnexion exécuté en local sur le poste compromis

<img width="1024" height="782" alt="image" src="https://github.com/user-attachments/assets/7df999df-b466-48ce-b337-e7a908874702" />
