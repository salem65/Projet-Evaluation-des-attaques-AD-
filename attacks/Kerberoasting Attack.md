L’attaque Pass-The-Hash nous a permis de faire un mouvement latéral pour ainsi
compromettre un compte qui a un plus de liberté d’action comme les comptes
SPN, ainsi le compte IT_2 a été compromis pour permettre de mener l’attaque
kerberoasting afin de recuperer le ticket d’un compte SPN pour augmenter les
privilèges et continuer la compromission du système.
L’objectif est de recuperer les ticket TGS qui contient le hash du compte SPN,
puis cracker le mot de passe off-line pour l’avoir en claire.


# Exploitation

```
impacket-GetUserSPNs lab-test.local/it_2:************* -dc-ip 192.168.174.133
```
