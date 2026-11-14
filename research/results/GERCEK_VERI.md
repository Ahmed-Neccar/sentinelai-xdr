# Gerçek saldırı kayıtlarında kural denemesi (OTRF Security-Datasets)

8 halka açık Windows saldırı kaydı (https://github.com/OTRF/Security-Datasets) üzerinde, yalnızca SentinelAI sensörünün topladığı Güvenlik günlüğü olayları dönüştürülerek yerleşik kurallar çalıştırıldı. **Beklenen kural, kayıt çalıştırılmadan önce, belgelenmiş tekniğe göre belirlendi.**

**Sonuç: 5 / 8 kayıtta beklenen kural en az bir bulgu üretti.** Bu bir duyarlılık ölçümüdür; kayıtlarda olay başına etiket olmadığı için yanlış pozitif oranı hesaplanamaz. "Diğer bulgular" sütunu laboratuvar ana bilgisayarının olağan gürültüsü ile saldırının diğer adımlarını karıştırır; yanlış alarm sayısı olarak okunmamalıdır.

| Kayıt | Teknik | Beklenen kural | Isabet | Dönüştürülen olay | Diğer bulgu sayısı |
|---|---|---|:-:|---:|---:|
| `empire_schtasks_creation_standard_user.zip` | T1053.005 scheduled task creation | `windows_scheduled_task_created` | evet | 3 / 198 | 0 |
| `empire_psexec_dcerpc_tcp_svcctl.zip` | T1569.002 service execution (PsExec-style) | `windows_service_installed` | **hayır** | 1 / 216 | 0 |
| `empire_wmic_add_user_backdoor.zip` | T1136.001 local account creation | `windows_account_created` | evet | 31 / 6138 | 2 |
| `auditpol_system_user_auditpolicy_modification.zip` | T1562.002 audit policy modification | `windows_audit_policy_changed` | evet | 83 / 307 | 1 |
| `empire_launcher_vbs.zip` | T1059.005 VBScript launcher | `wscript_spawns_powershell`, `cscript_spawns_powershell` | evet | 5 / 652 | 0 |
| `cmd_mshta_vbscript_execute_psh.zip` | T1218.005 mshta executing a script | `mshta_spawns_powershell` | evet | 4 / 233 | 1 |
| `empire_wmi_dcerpc_wmi_IWbemServices_ExecMethod.zip` | T1047 remote WMI execution | `wmi_spawns_powershell`, `wmi_spawns_cmd` | **hayır** | 4 / 2962 | 1 |
| `covenant_sharpwmi_create_dcerpc_wmi.zip` | T1047 remote WMI process creation | `wmi_spawns_powershell`, `wmi_spawns_cmd` | **hayır** | 6 / 622 | 1 |

## Kural bazında bulgular

- `empire_schtasks_creation_standard_user.zip`: `windows_scheduled_task_created`: 1
- `empire_psexec_dcerpc_tcp_svcctl.zip`: bulgu yok
- `empire_wmic_add_user_backdoor.zip`: `windows_account_created`: 1, `windows_scheduled_task_changed`: 1, `windows_security_group_member_added`: 1
- `auditpol_system_user_auditpolicy_modification.zip`: `process_from_downloads_folder`: 1, `windows_audit_policy_changed`: 1
- `empire_launcher_vbs.zip`: `wscript_spawns_powershell`: 1
- `cmd_mshta_vbscript_execute_psh.zip`: `mshta_spawns_powershell`: 1, `windows_security_log_cleared`: 1
- `empire_wmi_dcerpc_wmi_IWbemServices_ExecMethod.zip`: `windows_scheduled_task_changed`: 1
- `covenant_sharpwmi_create_dcerpc_wmi.zip`: `windows_scheduled_task_changed`: 1

## Iskalanan kayıtların çözümlemesi

Bu çözümlemeler kayıtlar incelendikten **sonra** yazıldı (beklenen kurallar ise önceden belirlenmişti):

- `empire_psexec_dcerpc_tcp_svcctl.zip`: Hizmet kurulumu Windows tarafından yalnızca Sistem günlüğünde 7045 olarak yazıldı; Güvenlik günlüğünde 4697 yok (bunun için "Güvenlik Sistemi Uzantısı" denetimi açık olmalı). Sensör yalnızca Güvenlik günlüğünü okuduğu için olay kurala hiç ulaşmadı: bu bir toplama boşluğudur, kural hatası değil.
- `empire_wmi_dcerpc_wmi_IWbemServices_ExecMethod.zip`: WmiPrvSE'in powershell.exe başlatması yalnızca Sysmon (olay 1) kaydında var. Bu kaydın Güvenlik günlüğünde WmiPrvSE süreci görünüyor ama PowerShell alt süreci yok; kuralın eşleşecek bir şeyi olmadı: bu bir veri kaynağı boşluğudur (sensör Sysmon okumaz).
- `covenant_sharpwmi_create_dcerpc_wmi.zip`: Güvenlik 4688 olayı WmiPrvSE.exe'nin GruntHTTP2.exe'yi (implant) başlattığını gösteriyor. WMI kuralları alt süreç olarak yalnızca powershell.exe ve cmd.exe'yi eşlediği için rastgele bir alt süreç ıskalanıyor: kural burada fazla dar. "WmiPrvSE'in herhangi bir alt süreci" kuralı bunu yakalardı; ancak yalnızca bu tek kayda göre ayarlanmış olacağı için eklenmedi. Önce ayrı bir kayıtla doğrulanması ve iyi huylu yönetim araçlarının maliyetinin ölçülmesi gerekir.

## Sınırlılıklar

- Yalnızca saldırı kayıtları kullanıldı; iyi huylu karşılık yok. Yanlış alarm ölçülmedi.
- 8 kayıt küçük bir örnektir ve her kural için tek bir teknik örneği vardır; genelleme yapılamaz.
- Kayıtlar laboratuvar ortamında (Windows 10 / Server 2016, Güvenlik günlüğünde süreç oluşturma denetimi açık) alınmıştır; süreç adları kayıtlardaki tam yollardır. Gerçek bir kurumda denetim ayarları farklı olabilir.
- Sensörün gerçek XML işleme yolu kullanılmadı; olaylar kayıtlardaki alanlardan aynı olay türü ve öznitelik adlarına dönüştürüldü.
