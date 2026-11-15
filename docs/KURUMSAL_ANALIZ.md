# SentinelAI XDR: kurumsal ürünlerle karşılaştırmalı analiz

Tarih: 2026-11-15. Amaç: bir şirkete satılabilecek bir güvenlik platformunun müşteri tarafında
(BT, güvenlik ekibi, denetçi, satın alma) nasıl değerlendirildiğini ortaya koymak ve SentinelAI'nin
bugünkü durumunu buna göre dürüstçe ölçmek.

**Kaynak notu.** Karşılaştırılan ürünlerin özellikleri yazarın genel bilgisinden alınmıştır; bu
oturumda satıcı belgelerinden tek tek doğrulanmadı. Satış görüşmesinde bir ürün hakkında iddia
kurmadan önce güncel belgesine bakın. SentinelAI sütunu ise bu depodaki koda ve testlere dayanır.

## 1. En yakın benzer: Wazuh

Wazuh, kendi sunucunuzda çalışan, açık kaynaklı bir XDR/SIEM'dir: uç nokta ajanları, kural tabanlı
tespit, MITRE ATT&CK eşlemesi, aktif müdahale (active response), uyumluluk panoları ve bir web
arayüzü sunar. SentinelAI'nin hedefiyle (kendi altyapısında çalışan, ajanlı, kural tabanlı tespit
ve müdahale) en çok örtüşen ürün odur. Büyük kurumlarda yaygın karşılaştırma noktaları da şunlardır:
Elastic Security, Microsoft Sentinel ile Defender XDR, CrowdStrike Falcon, Security Onion.

Bunlar nasıl çalışır (ortak kalıp):

1. **Kimlik:** Çalışanlar ürüne parola ile değil, şirket kimlik sağlayıcısıyla (Entra ID, Okta,
   Google) girer (SSO). MFA ve cihaz kuralları kimlik sağlayıcıda uygulanır. Yerel hesaplar
   yalnızca acil durum içindir.
2. **Hesap yaşam döngüsü:** İşe giriş, rol değişikliği ve ayrılış kimlik sağlayıcıdan SCIM ile
   otomatik akar. İnsan eliyle hesap açılmaz; kişi ayrılınca erişim aynı saatte kapanır.
3. **Yetki:** Kimlik sağlayıcıdaki gruplar, üründeki rollere eşlenir. Roller ayrıntılıdır (okuma,
   inceleme, müdahale onayı, yönetim) ve bazı eylemler ikinci bir onay ister.
4. **Denetim:** Her yönetici eylemi değiştirilemez biçimde kaydedilir, dışarı (SIEM, syslog)
   akıtılabilir ve uyumluluk denetiminde kanıt olarak sunulur.
5. **Operasyon:** Yedek, geri yükleme, sürüm yükseltme, izleme, yüksek erişilebilirlik, veri
   saklama politikası, kapasite planı belgelenmiştir.
6. **Entegrasyon:** Dışarıya API ve webhook, içeri çok sayıda veri kaynağı bağlayıcısı.

## 2. Boyut boyut karşılaştırma

Durum: **Var** (kodda ve testte), **Kısmi**, **Yok**. "Beklenti" sütunu kurumsal alıcının tipik
beklentisidir.

### 2.1 Kimlik ve erişim

| Konu | Kurumsal beklenti | SentinelAI bugün |
|---|---|---|
| SSO (OIDC) | Zorunlu | **Var.** PKCE, nonce, doğrulanmış e-posta, issuer+subject bağlama; Entra ile denendi |
| SAML | Büyük şirketlerin çoğunda istenir | **Yok** |
| MFA | Kimlik sağlayıcıda; yerel hesap için TOTP | **Var** (TOTP, kurtarma kodu, kurum geneli zorunlu kılma) |
| SCIM ile hesap yaşam döngüsü | Orta/büyük şirkette şart | **Var (bu oturumda eklendi):** kullanıcı oluştur/güncelle/kapat, filtre, PATCH, soft-delete. Grup (Groups) kaynağı yok |
| Gruptan role eşleme | Şart | **Var (bu oturumda eklendi):** groups/roles claim → rol, her girişte eşitleme, son yönetici korunur |
| İlk girişte hesap açma (JIT) | Sık | **Var (bu oturumda eklendi),** varsayılan kapalı; yalnızca eşlenmiş rolle |
| Oturum süresi | Mutlak limit + boşta zaman aşımı | **Var (bu oturumda eklendi):** 12 saat mutlak, 30 dk boşta (arayüz) |
| Oturum listesi / uzaktan sonlandırma | Beklenir | **Var (sonradan eklendi):** kişi kendi oturumlarını görür, birini veya diğerlerini anında sonlandırır; yönetici de bir hesabı her yerden çıkarır |
| Parola politikası | Uzunluk, yaygın parola, geçmiş | **Kısmi:** uzunluk, yaygın sözcük, hesap adı. Sızıntı listesi (HIBP) ve parola geçmişi yok |
| Hesap kilitleme | Beklenir | **Kısmi, bilinçli:** hız sınırı (adres ve hesap başına) ve başarısız giriş panosu var. Kalıcı kilit bilerek eklenmedi: saldırgana, kurbanı sürekli yanlış parolayla kilitleyip hizmet dışı bırakma imkânı verir |
| API anahtarları / servis hesapları | Beklenir | **Kısmi:** sensör hesapları var; kapsamlı, süreli API anahtarı yok |
| IP / ağ kısıtlaması | Sık | **Yok** |

### 2.2 Yetki ve onay

| Konu | Beklenti | SentinelAI |
|---|---|---|
| Rol modeli | Ayrıntılı, özelleştirilebilir | **Kısmi:** 4 sabit rol |
| İkinci onaylı riskli eylem | Müdahale için sık | **Var:** müdahale önerisini öneren kişi onaylayamaz |
| Çok kiracılık | MSSP / holding için | **Var:** PostgreSQL satır düzeyi güvenlik, testli |

### 2.3 Denetim ve uyumluluk

| Konu | Beklenti | SentinelAI |
|---|---|---|
| Yönetici eylemleri kaydı | Şart | **Var:** denetim günlüğü; yeni kimlik eylemleri de yazılıyor |
| Değiştirilemezlik / dışa akıtma | Beklenir | **Büyük ölçüde var (sonradan eklendi):** her kayıt bir öncekinin özetine bağlı (zincir), veritabanı tetikleyicisiyle; değiştirme reddedilir, ortadan silme zincir kontrolünde görünür; SIEM için sayfalı dışa aktarma. **Sınır:** en yeni kayıtların silinmesi veritabanından anlaşılamaz (özetin dışarıda kopyası gerekir), veritabanı yöneticisi tetikleyiciyi kapatabilir; syslog ile anlık itme yok, çekme (pull) var |
| Uyumluluk raporları (ISO 27001, SOC 2, KVKK eşlemesi) | Satışta sorulur | **Yok** |
| Veri saklama politikası | Şart | **Var** (yükleme dosyaları ve olaylar için gün bazlı) |

### 2.4 Tespit ve müdahale (ürünün özü)

| Konu | Beklenti | SentinelAI |
|---|---|---|
| Kural içeriği ve MITRE eşlemesi | Geniş kural kütüphanesi | **Kısmi:** sınırlı kural seti; ölçümler STATUS.md'de, gerçek veride sınırlı |
| Sigma kural içe aktarma | Sık | **Yok** |
| Ajan platformları | Windows, Linux, macOS | **Kısmi:** yalnızca Windows sensörü |
| Aktif müdahale | IP engelleme, cihaz yalıtma | **Var** (gerçek: Windows güvenlik duvarı, yalıtma, hesap kapatma), onay akışıyla |
| Vaka yönetimi | Şart | **Var** |
| Bildirim | E-posta, Slack, Teams | **Var** (kanal bazlı) |
| Bulut kaynakları | AWS, Azure, M365 | **Kısmi:** AWS CloudTrail, Azure etkinlik, Entra oturum |
| Tehdit istihbaratı beslemeleri | Beklenir | **Yok** |

### 2.5 Operasyon

| Konu | Beklenti | SentinelAI |
|---|---|---|
| Yedek / geri yükleme | Şart | **Var:** doğrulamalı yedek ve geri yükleme provası |
| Yüksek erişilebilirlik | Büyük müşteri | **Yok:** tek düğüm Docker Compose |
| Ölçek | Binlerce ajan | **Bilinmiyor:** yük testi betiği var, kurumsal ölçekte sonuç yok |
| İzleme | Beklenir | **Var:** metrik ve uyarı kuralları (Prometheus) |
| Sürüm yükseltme / sürüm notu | Beklenir | **Kısmi:** göç betikleri var; sürümleme ve yükseltme kılavuzu zayıf |
| Güvenlik testi / sızma testi raporu | Satışta istenir | **Yok** (yalnızca iç testler) |

### 2.6 Arayüz

Kurumsal alıcı için okunurluk ve tutarlılık ürünün güvenilirliğinin parçasıdır. Bu oturumda
yazı tipi yedekleri, küçük yazıların büyütülmesi, odak çerçevesi, iki adımlı parola penceresi
düzeltildi. Hâlâ eksik: tek tasarım sistemi (App.tsx hâlâ tek büyük dosya), tam mobil
denetimi, ekran okuyucu testi, açık ve yüksek kontrast tema taraması.

## 3. Sonuç: satışa hazır olmak için en önemli boşluklar

Öncelik sırası (etki / çaba):

1. **Güvenlik doğrulaması:** Bağımsız sızma testi ve bağımlılık taraması raporu. Kurumsal alıcı
   ilk bunu ister. Kendi başına yapılamaz; dış kaynak gerekir.
2. **SAML desteği** ve Okta/Google ile gerçek denemeler (şimdilik yalnızca Entra denendi).
3. **Denetim günlüğünün anlık itilmesi** (syslog / webhook) ve özetin dış bir kasaya yazılması (çekme ve zincir hazır).
4. ~~Kişinin kendi oturum listesi~~ (yapıldı).
5. **Linux sensörü** ve ajan güncelleme mekanizması.
6. **Yüksek erişilebilirlik ve ölçek ölçümü** (en az bir gerçekçi yük testi sonucu).
7. **Uyumluluk eşleme belgeleri** (ISO 27001 / KVKK madde eşlemesi) ve veri işleme belgesi.
8. **Rol özelleştirme** ve API anahtarları.
9. Kural kütüphanesi genişletme, Sigma içe aktarma, MITRE eşlemesi.

## 4. Bu oturumda yapılanlar ve doğrulama durumu

- SCIM 2.0 kullanıcı yönetimi, gruptan role eşleme, ilk girişte hesap açma, yönetici zorla çıkış:
  backend testleri yazıldı ve geçti; gerçek bir PostgreSQL'e göçle birlikte uçtan uca denendi
  (jeton oluşturma, kullanıcı oluşturma, filtreleme, silme).
- **Denenmedi:** Gerçek bir Microsoft Entra kiracısıyla SCIM sağlama ve `groups` claim'i. Entra
  tarafında "groups claim" ayarının açılması gerekir; çok gruba sahip kişilerde Entra grupları
  token'a koymayıp (overage) Graph çağrısı ister, bu desteklenmiyor (o durumda eşleme boş kalır,
  mevcut roller korunur).
- Bilinen sınır: SCIM jetonu yönetici rolü veremez (bilinçli güvenlik kararı); SCIM hata gövdesi
  standart SCIM hata şeklinde değil, uygulamanın kendi hata biçiminde (durum kodları doğru).
