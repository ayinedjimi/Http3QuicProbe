# 🚀 Http3QuicProbe


**Auteur**: Ayi NEDJIMI
**Version**: 1.0
**Date**: 2025-10-20

## 📋 Description

Http3QuicProbe est un outil de detection du support HTTP/3 et QUIC sur des serveurs distants. Il effectue des tests via WinHTTP et des probes UDP QUIC pour determiner si un serveur supporte les protocoles modernes HTTP/3 et QUIC.


## ✨ Fonctionnalites

- **Test HTTP/3**: Utilisation de WinHTTP pour tester le support HTTP/3
- **Detection ALPN**: Identification du protocole negocie (h3, h2, http/1.1)
- **Probe QUIC UDP**: Test de connectivite QUIC sur le port 443 UDP
- **Interface graphique**: Champ de saisie URL et ListView pour les resultats
- **URLs multiples**: Possibilite de tester plusieurs URLs successivement
- **Export CSV**: Sauvegarde des resultats avec encodage UTF-8 BOM
- **Logging**: Journalisation dans %TEMP%\WinTools_Http3QuicProbe_log.txt


## Compilation

### Prerequis

- Visual Studio 2019 ou superieur avec outils C++
- Windows SDK 10.0 ou superieur
- Windows 11 ou Windows Server 2022 recommande pour support HTTP/3 complet

### Commande de compilation

Executer `go.bat` depuis un "Developer Command Prompt for VS":

```batch
go.bat
```

Ou compiler manuellement:

```batch
cl.exe /EHsc /W4 /O2 /D UNICODE /D _UNICODE ^
    Http3QuicProbe.cpp ^
    /link ^
    comctl32.lib winhttp.lib ws2_32.lib user32.lib gdi32.lib ^
    /OUT:Http3QuicProbe.exe
```


## 🚀 Utilisation

1. Lancer `Http3QuicProbe.exe`
2. Entrer une URL HTTPS dans le champ (ex: https://www.cloudflare.com)
3. Cliquer sur "Tester" pour lancer le probe
4. Consulter les resultats dans le tableau
5. Tester d'autres URLs si necessaire
6. Cliquer sur "Exporter CSV" pour sauvegarder les resultats


## Colonnes du ListView

| Colonne | Description |
|---------|-------------|
| **URL** | URL testee |
| **HTTP/3 Support** | Oui / Non / Probable (QUIC repond) |
| **ALPN Protocol** | Protocole negocie (h3, h2, http/1.1, N/A) |
| **Notes** | Details techniques et observations |


## Interpretation des resultats

### HTTP/3 Support

- **Oui**: Le serveur supporte HTTP/3 et l'a utilise pour la requete
- **Non**: Le serveur ne supporte pas HTTP/3
- **Probable (QUIC repond)**: WinHTTP n'a pas pu etablir de connexion HTTP/3, mais le serveur repond aux probes QUIC UDP

### ALPN Protocol

- **h3**: HTTP/3 negocie et utilise
- **h2**: HTTP/2 negocie (fallback)
- **http/1.1**: HTTP/1.1 utilise (pas de support HTTP/2 ou HTTP/3)
- **N/A**: Impossible de determiner

### Notes typiques

- **HTTP/3 disponible et utilise**: Succes complet
- **HTTP/2 utilise, HTTP/3 non disponible**: Le serveur ne supporte que HTTP/2
- **Pas de HTTP/3 via WinHTTP, mais QUIC repond sur UDP 443**: Le serveur semble supporter QUIC mais WinHTTP ne peut pas etablir de connexion HTTP/3 (peut-etre une limitation de Windows)


## URLs de test recommandees

Serveurs connus pour supporter HTTP/3:
- https://www.cloudflare.com
- https://www.google.com
- https://www.facebook.com
- https://quic.nginx.org
- https://http3.is


## Technique de probe QUIC

L'outil envoie un packet QUIC Initial minimal pour declencher une reponse du serveur:
- Header: Long header avec flag Initial
- Version: QUIC v1 (0x00000001)
- Connection IDs: DCID vide, SCID de 8 octets aleatoire

Si le serveur repond (version negotiation ou autre), cela indique qu'il supporte QUIC.


## 🔌 APIs Win32 utilisees

- **winhttp.lib**: WinHttpOpen, WinHttpConnect, WinHttpOpenRequest, WinHttpSetOption (HTTP/3)
- **ws2_32.lib**: Socket UDP, sendto, recvfrom pour probes QUIC
- **comctl32.lib**: ListView (LVS_REPORT)


## Architecture

- **Monolithique**: Un seul fichier .cpp
- **Unicode**: Support complet UNICODE/UTF-16
- **Threading**: std::thread pour probes asynchrones
- **RAII**: Classe AutoHandle pour gestion automatique des ressources
- **Mutex**: Protection des acces concurrents aux resultats


## Format CSV

Le fichier CSV exporte contient:
- En-tete: URL;HTTP3Support;ALPNProtocol;Notes
- Encodage: UTF-8 avec BOM
- Separateur: Point-virgule (;)


## Logs

Les operations sont journalisees dans:
```
%TEMP%\WinTools_Http3QuicProbe_log.txt
```

Format: `YYYY-MM-DD HH:MM:SS - Message`


## Limitations connues

- Le support HTTP/3 dans WinHTTP necessite Windows 11 build 22000+ ou Windows Server 2022+
- Sur Windows 10, seuls les probes QUIC UDP fonctionnent
- Certains pare-feu peuvent bloquer le traffic UDP sur le port 443
- Les proxies d'entreprise peuvent interferer avec HTTP/3


## 🔧 Troubleshooting

### "HTTP/3 non disponible" alors que le serveur le supporte

- Verifiez la version de Windows (HTTP/3 necessite Windows 11+)
- Verifiez que le service QUIC est active: `sc query msquic`
- Testez avec le probe QUIC pour confirmer la connectivite UDP

### Timeouts frequents

- Verifiez la connectivite reseau
- Verifiez que le pare-feu autorise le traffic UDP sortant sur le port 443
- Essayez avec une URL connue pour supporter HTTP/3 (ex: cloudflare.com)


## 📄 Licence

Outil developpe par Ayi NEDJIMI dans le cadre de la suite WinToolsSuite.


## Support

Pour toute question ou suggestion, consulter la documentation de WinToolsSuite.


- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

---

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>