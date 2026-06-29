# 명령어 사용법
## audit-settings
`audit-settings` 명령어는 Windows 이벤트 로그 감사 정책 설정을 확인하고 이를 [Yamato Security](https://github.com/Yamato-Security/EnableWindowsLogSettings), [Microsoft(Sever/Client)](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations), [Australian Signals Directorate (ASD)](https://www.cyber.gov.au/resources-business-and-government/maintaining-devices-and-systems/system-hardening-and-administration/system-monitoring/windows-event-logging-and-forwarding)의 권장 설정과 비교합니다.
`RuleCount`는 해당 카테고리 내의 이벤트를 탐지할 수 있는 [Sigma 규칙](https://github.com/SigmaHQ/sigma)의 개수를 나타냅니다.

### `audit-settings` 명령어 예시
기본 Yamato Security의 권장 설정으로 확인하고 결과를 CSV로 저장:  
```
./WELA.ps1 audit-settings -Baseline YamatoSecurity
```

Australian Signals Directorate의 권장 설정으로 확인하고 결과를 CSV로 저장:  
```
./WELA.ps1 audit-settings -Baseline ASD
```

Microsoft의 권장 Server OS 설정으로 확인하고 결과를 GUI로 표시:  
```
./WELA.ps1 audit-settings -Baseline Microsoft_Server -OutType gui
```

Microsoft의 권장 Client OS 설정으로 확인하고 결과를 테이블 형식으로 표시:  
```
./WELA.ps1 audit-settings -Baseline Microsoft_Client -OutType table
```

## audit-filesize
`audit-filesize` 명령어는 Windows 이벤트 로그의 파일 크기를 확인하고 이를 Yamato Security의 권장 설정과 비교합니다.

### `audit-filesize` 명령어 예시
Yamato Security의 권장 설정으로 Windows 이벤트 로그 파일 크기를 확인하고 결과를 CSV로 저장:  
```
./WELA.ps1 audit-filesize -Baseline YamatoSecurity
```

## configure
`configure` 명령어는 권장되는 Windows 이벤트 로그 감사 정책과 파일 크기를 설정합니다.

#### `configure` 명령어 예시
Yamato Security의 권장 설정 적용(설정 변경 전 확인 프롬프트 포함):
```
./WELA.ps1 configure -Baseline YamatoSecurity
```

Australian Signals Directorate의 권장 설정을 확인 프롬프트 없이 적용:
```
./WELA.ps1 configure -Baseline ASD -auto
```

## update-rules
#### `update-rules` 명령어 예시
WELA의 Sigma 규칙 구성 파일 업데이트:  
```
./WELA.ps1 update-rules
```
