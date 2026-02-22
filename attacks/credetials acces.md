# Pre-reauis : Avoir un shell meterpreter actif sur la machine de la cible
# Obtenir le hash NTLM de l'utilisateur 
# Escalade de privilege pour extraire les identifiants d'un domain AD

Ici l’attaquant va utiliser le module kiwi qui est une extension Meterpreter qui permet d'utiliser les fonctionnalités de Mimikatz. La commande ‘‘kiwi_cmd sekurlsa::logonpasswords’’ va injecter un "reflector DLL" ou un shellcode qui utilise les API internes de Windows pour extraire les secrets depuis les structures de mémoire de LSASS.
Nous lançons msfconsole pour initier l’écoute sur le port 6887 défini dans le payload. Nous chargeons ensuite le module kiwi pour nous permettre d’extraire les identifiants de l’utilisateur.

## Exploitation

```
load kiwi

kiwi_cmd sekurlsa::logonpasswords
```
