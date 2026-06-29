# Uso de comandos
## audit-settings
El comando `audit-settings` comprueba la configuración de la política de auditoría del registro de eventos de Windows y la compara con la configuración recomendada de [Yamato Security](https://github.com/Yamato-Security/EnableWindowsLogSettings), [Microsoft(Sever/Client)](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations) y [Australian Signals Directorate (ASD)](https://www.cyber.gov.au/resources-business-and-government/maintaining-devices-and-systems/system-hardening-and-administration/system-monitoring/windows-event-logging-and-forwarding).
`RuleCount` indica el número de [reglas Sigma](https://github.com/SigmaHQ/sigma) que pueden detectar eventos dentro de esa categoría.

### Ejemplos del comando `audit-settings`
Comprobar con la configuración recomendada predeterminada de Yamato Security y guardar los resultados en CSV:  
```
./WELA.ps1 audit-settings -Baseline YamatoSecurity
```

Comprobar con la configuración recomendada de Australian Signals Directorate y guardar los resultados en CSV:  
```
./WELA.ps1 audit-settings -Baseline ASD
```

Comprobar con la configuración recomendada de Microsoft para SO de servidor y mostrar los resultados en una GUI:  
```
./WELA.ps1 audit-settings -Baseline Microsoft_Server -OutType gui
```

Comprobar con la configuración recomendada de Microsoft para SO de cliente y mostrar los resultados en formato de tabla:  
```
./WELA.ps1 audit-settings -Baseline Microsoft_Client -OutType table
```

## audit-filesize
El comando `audit-filesize` comprueba el tamaño de archivo de los registros de eventos de Windows y lo compara con la configuración recomendada de las recomendaciones de Yamato Security.

### Ejemplos del comando `audit-filesize`
Comprobar el tamaño de archivo del registro de eventos de Windows con las recomendaciones de Yamato Security y guardar los resultados en CSV:  
```
./WELA.ps1 audit-filesize -Baseline YamatoSecurity
```

## configure
El comando `configure` establece la política de auditoría del registro de eventos de Windows y el tamaño de archivo recomendados.

#### Ejemplos del comando `configure`
Aplicar la configuración recomendada de Yamato Security (con solicitud de confirmación antes de cambiar la configuración):
```
./WELA.ps1 configure -Baseline YamatoSecurity
```

Aplicar la configuración recomendada de Australian Signals Directorate sin solicitud de confirmación:
```
./WELA.ps1 configure -Baseline ASD -auto
```

## update-rules
#### Ejemplos del comando `update-rules`
Actualizar los archivos de configuración de reglas Sigma de WELA:  
```
./WELA.ps1 update-rules
```
