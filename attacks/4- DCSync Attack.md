L'attaque Dcsync est l'une des techniques les plus redoutables et les plus
"silencieuses" dans un environnement Active Directory.
Dans un réseau Windows, lorsqu'il y a plusieurs Contrôleurs de Domaine, ils
doivent synchroniser leurs données (utilisateurs, mots de passe, etc.) via le
protocole MS-DRSR (Directory Replication Service Remote Protocol ).
L'attaque Dcsync consiste à utiliser un compte qui possède des privilèges de
réplication (dans notre cas le compte « Administrateur ») pour simuler un
nouveau Contrôleur de Domaine et demander au DC principal de lui envoyer les
hashs de mots de passe.
Ici nous allons utiliser impacket-secretsdump, il va contacter le DC et invoquer la
fonction GetNCChanges. Le Contrôleur de Domaine, croyant parler à un
homologue légitime, renvoie les données demandées. On récupère alors le hash NTLM (ou les clés Kerberos) de n'importe quel utilisateur, notamment celui du
compte krbtgt (pour créer un Golden Ticket).
Donc l’attaque est effectuer avec le hash cracker du compte Administrateur
recuperer lors de l’attaque Kerberoasting pour recuperer le hash du compte
KRBTGT. Ce compte est utilisé par le service Kerberos pour signer et chiffrer tous
les tickets (TGT).



```
secretsdump.py LAB-TEST.LOCAL/Administrateur:***********@192.168.174.133 -just-dc-user krbtgt
```


<img width="1614" height="347" alt="DCSync" src="https://github.com/user-attachments/assets/3fbd9e00-2b50-46e7-9c08-7eb609c37dfc" />
