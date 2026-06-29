# Uso de Comandos
## audit-settings
O comando `audit-settings` verifica as configurações da política de auditoria do log de eventos do Windows e as compara com as configurações recomendadas da [Yamato Security](https://github.com/Yamato-Security/EnableWindowsLogSettings), da [Microsoft(Sever/Client)](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations) e da [Australian Signals Directorate (ASD)](https://www.cyber.gov.au/resources-business-and-government/maintaining-devices-and-systems/system-hardening-and-administration/system-monitoring/windows-event-logging-and-forwarding).
`RuleCount` indica o número de [regras Sigma](https://github.com/SigmaHQ/sigma) que podem detectar eventos dentro daquela categoria.

### exemplos do comando `audit-settings`
Verifique com as configurações recomendadas padrão da Yamato Security e salve os resultados em CSV:  
```
./WELA.ps1 audit-settings -Baseline YamatoSecurity
```

Verifique com as configurações recomendadas da Australian Signals Directorate e salve os resultados em CSV:  
```
./WELA.ps1 audit-settings -Baseline ASD
```

Verifique com as configurações recomendadas da Microsoft para SO Server e exiba os resultados em uma GUI:  
```
./WELA.ps1 audit-settings -Baseline Microsoft_Server -OutType gui
```

Verifique com as configurações recomendadas da Microsoft para SO Client e exiba os resultados em formato de tabela:  
```
./WELA.ps1 audit-settings -Baseline Microsoft_Client -OutType table
```

## audit-filesize
O comando `audit-filesize` verifica o tamanho dos arquivos dos logs de eventos do Windows e os compara com as configurações recomendadas pela Yamato Security.

### exemplos do comando `audit-filesize`
Verifique o tamanho do arquivo do log de eventos do Windows com as recomendações da Yamato Security e salve os resultados em CSV:  
```
./WELA.ps1 audit-filesize -Baseline YamatoSecurity
```

## configure
O comando `configure` define a política de auditoria recomendada do log de eventos do Windows e o tamanho do arquivo.

#### exemplos do comando `configure`
Aplique as configurações recomendadas da Yamato Security (com prompt de confirmação antes de alterar as configurações):
```
./WELA.ps1 configure -Baseline YamatoSecurity
```

Aplique as configurações recomendadas da Australian Signals Directorate sem prompt de confirmação:
```
./WELA.ps1 configure -Baseline ASD -auto
```

## update-rules
#### exemplos do comando `update-rules`
Atualize os arquivos de configuração das regras Sigma do WELA:  
```
./WELA.ps1 update-rules
```
