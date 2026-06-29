# การใช้งานคำสั่ง
## audit-settings
คำสั่ง `audit-settings` จะตรวจสอบการตั้งค่านโยบายการตรวจสอบ (audit policy) ของ Windows event log และเปรียบเทียบกับการตั้งค่าที่แนะนำจาก [Yamato Security](https://github.com/Yamato-Security/EnableWindowsLogSettings), [Microsoft(Sever/Client)](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations), และ [Australian Signals Directorate (ASD)](https://www.cyber.gov.au/resources-business-and-government/maintaining-devices-and-systems/system-hardening-and-administration/system-monitoring/windows-event-logging-and-forwarding)
`RuleCount` แสดงจำนวน [Sigma rules](https://github.com/SigmaHQ/sigma) ที่สามารถตรวจจับเหตุการณ์ภายในหมวดหมู่นั้นได้

### ตัวอย่างคำสั่ง `audit-settings`
ตรวจสอบด้วยการตั้งค่าที่แนะนำของ Yamato Security ซึ่งเป็นค่าเริ่มต้นและบันทึกผลลัพธ์เป็น CSV:  
```
./WELA.ps1 audit-settings -Baseline YamatoSecurity
```

ตรวจสอบด้วยการตั้งค่าที่แนะนำของ Australian Signals Directorate และบันทึกผลลัพธ์เป็น CSV:  
```
./WELA.ps1 audit-settings -Baseline ASD
```

ตรวจสอบด้วยการตั้งค่า Server OS ที่แนะนำของ Microsoft และแสดงผลลัพธ์ใน GUI:  
```
./WELA.ps1 audit-settings -Baseline Microsoft_Server -OutType gui
```

ตรวจสอบด้วยการตั้งค่า Client OS ที่แนะนำของ Microsoft และแสดงผลลัพธ์ในรูปแบบตาราง:  
```
./WELA.ps1 audit-settings -Baseline Microsoft_Client -OutType table
```

## audit-filesize
คำสั่ง `audit-filesize` จะตรวจสอบขนาดไฟล์ของ Windows event logs และเปรียบเทียบกับการตั้งค่าที่แนะนำจาก Yamato Security

### ตัวอย่างคำสั่ง `audit-filesize`
ตรวจสอบขนาดไฟล์ Windows event log ด้วยคำแนะนำของ Yamato Security และบันทึกผลลัพธ์เป็น CSV:  
```
./WELA.ps1 audit-filesize -Baseline YamatoSecurity
```

## configure
คำสั่ง `configure` จะตั้งค่านโยบายการตรวจสอบ (audit policy) ของ Windows event log และขนาดไฟล์ตามที่แนะนำ

#### ตัวอย่างคำสั่ง `configure`
ใช้การตั้งค่าที่แนะนำของ Yamato Security (พร้อมข้อความยืนยันก่อนการเปลี่ยนแปลงการตั้งค่า):
```
./WELA.ps1 configure -Baseline YamatoSecurity
```

ใช้การตั้งค่าที่แนะนำของ Australian Signals Directorate โดยไม่มีข้อความยืนยัน:
```
./WELA.ps1 configure -Baseline ASD -auto
```

## update-rules
#### ตัวอย่างคำสั่ง `update-rules`
อัปเดตไฟล์ config ของ Sigma rules ของ WELA:  
```
./WELA.ps1 update-rules
```
