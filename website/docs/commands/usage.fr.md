# Utilisation des commandes
## audit-settings
La commande `audit-settings` vérifie les paramètres de la stratégie d'audit du journal d'événements Windows et les compare aux paramètres recommandés par [Yamato Security](https://github.com/Yamato-Security/EnableWindowsLogSettings), [Microsoft(Sever/Client)](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations) et l'[Australian Signals Directorate (ASD)](https://www.cyber.gov.au/resources-business-and-government/maintaining-devices-and-systems/system-hardening-and-administration/system-monitoring/windows-event-logging-and-forwarding).
`RuleCount` indique le nombre de [règles Sigma](https://github.com/SigmaHQ/sigma) capables de détecter des événements dans cette catégorie.

### Exemples de la commande `audit-settings`
Vérifier avec les paramètres recommandés par défaut de Yamato Security et enregistrer les résultats au format CSV :  
```
./WELA.ps1 audit-settings -Baseline YamatoSecurity
```

Vérifier avec les paramètres recommandés par l'Australian Signals Directorate et enregistrer les résultats au format CSV :  
```
./WELA.ps1 audit-settings -Baseline ASD
```

Vérifier avec les paramètres recommandés par Microsoft pour les systèmes d'exploitation Server et afficher les résultats dans une interface graphique :  
```
./WELA.ps1 audit-settings -Baseline Microsoft_Server -OutType gui
```

Vérifier avec les paramètres recommandés par Microsoft pour les systèmes d'exploitation Client et afficher les résultats sous forme de tableau :  
```
./WELA.ps1 audit-settings -Baseline Microsoft_Client -OutType table
```

## audit-filesize
La commande `audit-filesize` vérifie la taille des fichiers des journaux d'événements Windows et la compare aux paramètres recommandés par Yamato Security.

### Exemples de la commande `audit-filesize`
Vérifier la taille des fichiers du journal d'événements Windows avec les recommandations de Yamato Security et enregistrer les résultats au format CSV :  
```
./WELA.ps1 audit-filesize -Baseline YamatoSecurity
```

## configure
La commande `configure` définit la stratégie d'audit du journal d'événements Windows et la taille des fichiers recommandées.

#### Exemples de la commande `configure`
Appliquer les paramètres recommandés par Yamato Security (avec une invite de confirmation avant de modifier les paramètres) :
```
./WELA.ps1 configure -Baseline YamatoSecurity
```

Appliquer les paramètres recommandés par l'Australian Signals Directorate sans invite de confirmation :
```
./WELA.ps1 configure -Baseline ASD -auto
```

## update-rules
#### Exemples de la commande `update-rules`
Mettre à jour les fichiers de configuration des règles Sigma de WELA :  
```
./WELA.ps1 update-rules
```
