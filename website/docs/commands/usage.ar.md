# استخدام الأوامر
## audit-settings
يتحقق الأمر `audit-settings` من إعدادات سياسة تدقيق سجل أحداث Windows ويقارنها بالإعدادات الموصى بها من [Yamato Security](https://github.com/Yamato-Security/EnableWindowsLogSettings) و[Microsoft(Sever/Client)](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations) و[Australian Signals Directorate (ASD)](https://www.cyber.gov.au/resources-business-and-government/maintaining-devices-and-systems/system-hardening-and-administration/system-monitoring/windows-event-logging-and-forwarding).
يشير `RuleCount` إلى عدد [قواعد Sigma](https://github.com/SigmaHQ/sigma) التي يمكنها اكتشاف الأحداث ضمن تلك الفئة.

### أمثلة على أمر `audit-settings`
التحقق باستخدام إعدادات Yamato Security الموصى بها الافتراضية وحفظ النتائج إلى CSV:  
```
./WELA.ps1 audit-settings -Baseline YamatoSecurity
```

التحقق باستخدام إعدادات Australian Signals Directorate الموصى بها وحفظ النتائج إلى CSV:  
```
./WELA.ps1 audit-settings -Baseline ASD
```

التحقق باستخدام إعدادات Microsoft الموصى بها لنظام تشغيل الخادم وعرض النتائج في واجهة رسومية:  
```
./WELA.ps1 audit-settings -Baseline Microsoft_Server -OutType gui
```

التحقق باستخدام إعدادات Microsoft الموصى بها لنظام تشغيل العميل وعرض النتائج في صيغة جدول:  
```
./WELA.ps1 audit-settings -Baseline Microsoft_Client -OutType table
```

## audit-filesize
يتحقق الأمر `audit-filesize` من حجم ملفات سجلات أحداث Windows ويقارنها بالإعدادات الموصى بها من توصيات Yamato Security.

### أمثلة على أمر `audit-filesize`
التحقق من حجم ملف سجل أحداث Windows باستخدام توصيات Yamato Security وحفظ النتائج إلى CSV:  
```
./WELA.ps1 audit-filesize -Baseline YamatoSecurity
```

## configure
يضبط الأمر `configure` سياسة تدقيق سجل أحداث Windows الموصى بها وحجم الملف.

#### أمثلة على أمر `configure`
تطبيق إعدادات Yamato Security الموصى بها (مع مطالبة تأكيد قبل تغيير الإعدادات):
```
./WELA.ps1 configure -Baseline YamatoSecurity
```

تطبيق إعدادات Australian Signals Directorate الموصى بها دون مطالبة تأكيد:
```
./WELA.ps1 configure -Baseline ASD -auto
```

## update-rules
#### أمثلة على أمر `update-rules`
تحديث ملفات إعدادات قواعد Sigma الخاصة بـ WELA:  
```
./WELA.ps1 update-rules
```
