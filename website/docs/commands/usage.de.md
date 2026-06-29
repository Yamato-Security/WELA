# Befehlsverwendung
## audit-settings
Der Befehl `audit-settings` überprüft die Einstellungen der Überwachungsrichtlinie des Windows-Ereignisprotokolls und vergleicht sie mit den empfohlenen Einstellungen von [Yamato Security](https://github.com/Yamato-Security/EnableWindowsLogSettings), [Microsoft(Sever/Client)](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations) und [Australian Signals Directorate (ASD)](https://www.cyber.gov.au/resources-business-and-government/maintaining-devices-and-systems/system-hardening-and-administration/system-monitoring/windows-event-logging-and-forwarding).
`RuleCount` gibt die Anzahl der [Sigma-Regeln](https://github.com/SigmaHQ/sigma) an, die Ereignisse innerhalb dieser Kategorie erkennen können.

### `audit-settings`-Befehlsbeispiele
Mit den standardmäßig empfohlenen Einstellungen von Yamato Security überprüfen und Ergebnisse als CSV speichern:  
```
./WELA.ps1 audit-settings -Baseline YamatoSecurity
```

Mit den empfohlenen Einstellungen des Australian Signals Directorate überprüfen und Ergebnisse als CSV speichern:  
```
./WELA.ps1 audit-settings -Baseline ASD
```

Mit den von Microsoft empfohlenen Einstellungen für Server-Betriebssysteme überprüfen und Ergebnisse in einer GUI anzeigen:  
```
./WELA.ps1 audit-settings -Baseline Microsoft_Server -OutType gui
```

Mit den von Microsoft empfohlenen Einstellungen für Client-Betriebssysteme überprüfen und Ergebnisse im Tabellenformat anzeigen:  
```
./WELA.ps1 audit-settings -Baseline Microsoft_Client -OutType table
```

## audit-filesize
Der Befehl `audit-filesize` überprüft die Dateigröße der Windows-Ereignisprotokolle und vergleicht sie mit den Empfehlungen von Yamato Security.

### `audit-filesize`-Befehlsbeispiele
Die Dateigröße des Windows-Ereignisprotokolls mit den Empfehlungen von Yamato Security überprüfen und Ergebnisse als CSV speichern:  
```
./WELA.ps1 audit-filesize -Baseline YamatoSecurity
```

## configure
Der Befehl `configure` legt die empfohlene Überwachungsrichtlinie und Dateigröße des Windows-Ereignisprotokolls fest.

#### `configure`-Befehlsbeispiele
Die von Yamato Security empfohlenen Einstellungen anwenden (mit Bestätigungsaufforderung vor dem Ändern der Einstellungen):
```
./WELA.ps1 configure -Baseline YamatoSecurity
```

Die vom Australian Signals Directorate empfohlenen Einstellungen ohne Bestätigungsaufforderung anwenden:
```
./WELA.ps1 configure -Baseline ASD -auto
```

## update-rules
#### `update-rules`-Befehlsbeispiele
Die Sigma-Regel-Konfigurationsdateien von WELA aktualisieren:  
```
./WELA.ps1 update-rules
```
