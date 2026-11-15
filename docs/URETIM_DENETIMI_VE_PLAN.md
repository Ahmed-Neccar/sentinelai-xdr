# Üretim olgunluğu: denetim raporu ve düzeltme planı

Tarih: 2026-11-15. Durum: denetim raporu yazıldı; **onay sonrası uygulama başladı** (sıra 1→2→4→3→5, bölüm 5'e bakın).

## 0. Kapsam ve dürüst sınırlar

**Okunan ve doğrulananlar:** tüm API uç noktalarının yetki bağımlılıkları (kaynak kodun AST
taramasıyla), müdahale aksiyonu yaşam döngüsü (`cases.py`, `ingest.py`, `response/ip_block.py`),
sensör kuyruklama ve yeniden bağlanma (`sensor/live_sensor.py`), yerel denetleyici
(`sensor/controller.py`), oturum ve kimlik kodu (bu oturumdaki önceki işler dahil), nginx başlıkları,
hız sınırlama kullanım yerleri.

**Bu raporda ayrıntılı incelenmeyenler (açık bırakıldı):** olay alım (`/events`) ve dosya yükleme
ayrıştırıcılarındaki girdi doğrulamasının her alanı, SQL katmanındaki tüm sorgular, bulut
bağlayıcı kimlik bilgisi saklama şifrelemesinin ayrıntıları, bağımlılık zafiyet taraması, Docker
imaj sertleştirmesi. Bunlar plana "keşif" adımı olarak eklendi. Bu rapor bir sızma testi yerine
geçmez.

**Önemli düzeltme:** İsteğinizdeki bazı maddeler kısmen zaten var. Yanlış bir "sıfırdan yaz"
planı kurmamak için ne olduğunu aşağıda açıkça ayırdım.

## 1. Mevcut durumda zaten olanlar

| Alan | Durum (kodda doğrulandı) |
|---|---|
| Müdahale yaşam döngüsü | `proposed → approved → (pending → applied / refused / failed → removal_pending → removed) / cancelled / expired`. Geçişler `next_status()` ile sınırlı, satır kilidiyle (`with_for_update`), öneren kişi onaylayamaz, tekrar eden rapor etkisiz |
| Teslim süresi | Onaylanan aksiyon 15 dakikada sensöre ulaşmazsa iptal ve denetim kaydı (`DELIVERY_WINDOW`) |
| Sensör ve yetenek denetimi | Gerçek aksiyon teklifi, "aktif" ve yeteneği duyurmuş bir sensör ister; hedef doğrulanır (IP, hesap adı, korumalı adresler) |
| RBAC | Taranan tüm uç noktalar bir yetki bağımlılığına bağlı (tarama aracım bazı ingest uçlarını listelemedi, onları elle teyit ettim); genel olanlar yalnızca giriş akışı, SSO, sağlık ve `/metrics` (jetonlu) |
| Sensör yönetimi arayüzü | Kayıt (enrollment), iptal (revoke), kimlik bilgisi yenileme arayüzde var (`App.tsx` Sensors bölümü) |
| Sensör kuyruğu | Gönderilemeyen olay paketleri diske yazılır (`spool/`), sonra sırayla yeniden gönderilir; iptal edilince sensör durur |
| Denetim günlüğü | Zincirli özet, güncelleme reddi, dışa aktarma (bu oturumda eklendi) |

## 2. Bulgular (öncelik sırasıyla)

Önem: **Y** yüksek, **O** orta, **D** düşük. "Doğrulandı" = kodu okuyarak teyit ettim.

### Müdahale yaşam döngüsü (istek madde 1)

| # | Bulgu | Önem |
|---|---|---|
| A1 | **Sensörün çevrimiçi olup olmadığı teklif ve onayda denetlenmiyor.** `_enforcing_sensors()` yalnızca kaydın `active` olmasına bakar; `last_seen_at` hiç karşılaştırılmaz. Çevrimdışı bir sensör için "Gerçek cihaz yalıtma" teklif edilip onaylanabilir; aksiyon `pending` bekler. Çevrimiçi göstergesi yalnızca arayüzdedir (120 sn). Doğrulandı | Y |
| A2 | **Süre aşımı yalnızca sensör bağlanınca çalışır.** 15 dakikalık teslim penceresi, `_pending_response_actions()` içinde, sensörün kalp atışı sırasında kontrol edilir. Sensör bir daha hiç gelmezse kayıt sonsuza dek `pending` kalır, bildirim ve iptal olmaz. Arka plan süpürmesi yok. Doğrulandı | Y |
| A3 | **"dispatched" durumu yok.** Sensöre teslim edilmiş ve henüz sonuç dönmemiş aksiyon ile hiç teslim edilmemiş aksiyon aynı `pending` durumunda. Teslim zamanı kaydedilmiyor; teslim edildi ama sensör çöktü durumu ayırt edilemiyor ve sonuç için zaman aşımı yok. Doğrulandı | Y |
| A4 | **Onay anında yeniden doğrulama yok.** Teklifle onay arasında sensör gitmiş olabilir (24 saate kadar); onay yalnızca öneri durumuna ve süreye bakar, sensörün hâlâ yetkili ve çevrimiçi olduğuna bakmaz. Doğrulandı | Y |
| A5 | **Yerel denetleyici durumu sunucuya yansımıyor.** `127.0.0.1:8765` kapalıysa bunu yalnızca tarayıcı görür; sunucu bilmez. Başlat/durdur akışı arayüzde hata mesajı gösterir ama teklif/onay akışı denetleyiciyi hiç dikkate almaz. Doğrulandı | O |
| A6 | `failed` / `refused` sonuçları kullanıcıya görünür mü: arayüz `enforcement_detail`'i gösteriyor (`detail[:255]`); ancak hata kodu yapısal değil, serbest metin; panoda sayaç ve uyarı yok. Kısmen doğrulandı | O |
| A7 | **Düzeltme:** İlk sürümde "sunucu tarafı çevrimdışı bildirimi yok" yazmıştım; bu yanlıştı. `notifications/health.py` 5 dakika sessiz kalan sensör için zaten bildirim kuyruğa alıyor (Celery, 5 dakikada bir). Eksik olan: 45 sn'lik anlık çevrimiçi/çevrimdışı gösterimi ve eylem akışına bağlanması (A1) | D |

### Güvenlik ve yetkilendirme (madde 2)

| # | Bulgu | Önem |
|---|---|---|
| B1 | **Hız sınırlama yalnızca kimlik, SCIM ve kullanıcı uçlarında.** Olay alımı, dosya yükleme, vaka, arama, dışa aktarma dahil diğer tüm uç noktalarda ve nginx'te `limit_req` yok. Ele geçirilmiş bir hesap veya jeton sınırsız istek atabilir. Doğrulandı | Y |
| B2 | **Sensör hesabı yönetici parolasına denk bir sır taşıyor.** Sensör, parola ile `/auth/login` yapıyor ve parolayı yerelde saklıyor (`read_project_credentials`). Çalınan sensör bilgisayarı, o hesabın izinleriyle API'ye girer. İmzalı kalp atışı (`_verify_registered_sensor_request`) bunu kısmen hafifletiyor. Kısmen doğrulandı | O |
| B3 | **Yerel denetleyici yalnızca `Origin` başlığına güveniyor.** Aynı bilgisayardaki herhangi bir işlem bu başlığı taklit edip sensörü başlatıp durdurabilir. Belirteç yok. Doğrulandı | O |
| B4 | `/health`, `/ready` herkese açık; `/metrics` jetonla korunuyor. `/ready` ayrıntı sızdırıyor mu: incelenmedi | D |
| B5 | **HSTS:** `deploy/tls-lab/nginx.conf` bilerek HSTS göndermiyor (yorumu: "localhost" üzerindeki tüm portları etkilerdi) ve "üretim yapılandırması değildir" diyor. Gerçek bir üretim ters vekili müşteri ortamına özgüdür; HSTS ve `limit_req` orada ayarlanmalı (DEPLOYMENT.md'ye not eklendi). Kod hatası değil, dağıtım notu | D |
| B6 | RBAC genel olarak sağlam; ancak rol kümeleri kodda dağınık (`Reader`, `AllowedList`, `LiveSensorUser`, `READ_EVENTS`...). Yeni uç nokta eklenirken yetki unutulması riski var; "her uç nokta bir yetki bildirmeli" kuralını zorlayan bir test yok. Doğrulandı | O |
| B7 | Denetim günlüğü: kimlik eylemleri kayıtlı; **okuma eylemleri** (denetim dışa aktarma, kullanıcı listesi gibi hassas okumalar) kaydedilmiyor. Dışa itme yok, yalnızca çekme. Doğrulandı | O |
| B8 | Sonradan fark edilen: oturum 12 saatte biter; **sensör** hesabı bu süreyi yenilemede otomatik tekrar giriş ile aşıyor (tasarım gereği), bu yüzden sensör oturumu mutlak sınıra bağlı değil | D |

### Uçtan uca arayüz (madde 3)

| # | Bulgu | Önem |
|---|---|---|
| C1 | Kayıt, iptal ve yenileme arayüzde var. Eksik olan: **sensör kaydı sırasında üretilen kayıt anahtarının tek seferlik gösterimi ve kopyalama akışı** doğrulanmadı; sensörü bu anahtarla kuracak komut/betik hâlâ terminal gerektirebilir (`start_sensor_controller.ps1`). Kısmen doğrulandı | O |
| C2 | Sensör kurulum paketi (`package_sensor.ps1`) terminal betiği; arayüzden indirilebilir bir kurulum paketi ve tek satırlık kurulum yok | O |
| C3 | Sensör durum sayfası: son görülme, sürüm, yetenekler var; **sürüm güncelliği, sağlık uyarısı ve çevrimdışı bildirimi** yok (A7 ile ortak) | O |

### Dayanıklılık (madde 4)

| # | Bulgu | Önem |
|---|---|---|
| D1 | **Kuyruk sınırsız büyüyebilir.** `spool/` boyutu ve dosya sayısı sınırsız; uzun kesintide disk dolabilir. Eski veriyi atma/öncelik politikası yok. Doğrulandı | Y |
| D2 | **Yeniden deneme geri çekilmesi (backoff) yok.** Başarısız kalp atışı ve boşaltma her 10 sn / `flush_seconds`'te sabit aralıkla denenir; sunucu geri döndüğünde tüm sensörler aynı anda saldırır (thundering herd), rastgelelik (jitter) yok. Doğrulandı | O |
| D3 | **Kuyruk dosyaları atomik yazılmıyor** (`write_text` doğrudan hedefe); yazım sırasında çökme yarım dosya bırakır ve boşaltma o dosyada takılabilir (`break`). Doğrulandı | O |
| D4 | **Zehirli dosya:** bozuk bir kuyruk dosyası `break` ile tüm sonraki dosyaların boşaltılmasını engeller; karantinaya alma yok. Doğrulandı | O |
| D5 | Sensör yeniden bağlandığında **sunucu tarafında yinelenen olay** koruması (idempotency) olay düzeyinde var mı doğrulanmadı | O |
| D6 | Yerel servis izleme: denetleyici `SensorSupervisor.status()` var; sensör işlemi çökerse **otomatik yeniden başlatma** mekanizması ve çökme sayacı doğrulanmadı (bir otomatik başlatma görevi betiği var) | O |
| D7 | Sunucu tarafında Celery işçi/beat sağlığı `/system/health` ile görünüyor; ancak kuyruk derinliği ve ölü-mektup (dead letter) izleme doğrulanmadı | D |

### Testler (madde 5)

| # | Bulgu | Önem |
|---|---|---|
| E1 | Backend 299, sensör 67, arayüz 25 test geçiyor. A1–A4 için **çevrimdışı sensör** senaryosu testi yok (A1'in varlığı bunun işareti). Kuyruk için sınır, atomiklik, zehirli dosya testi yok | Y |
| E2 | "Her uç nokta yetki bildirmeli" bütünlük testi yok (B6) | O |
| E3 | Yoğunluk altında denetim zinciri ve oturum tablosu performansı ölçülmedi | O |
| E4 | Sensör Windows'a özgü; Linux CI'da bazı sensör testleri çalışmaz (bu oturumda Windows venv ile geçti) | D |

## 3. Düzeltme planı (onay bekleyen)

Her adım: önce hatayı gösteren test, sonra düzeltme, sonra tüm testler. Adımlar birbirinden bağımsız
commit'lenir; canlıya alma her aşama sonunda ayrıca sorulur.

**Aşama 1: Müdahale yaşam döngüsü (A1–A7, E1)**
1. Sensör canlılığı kavramı: `last_seen_at` eşiği (ör. 45 sn) ile tek bir `sensor_is_online()`.
   Teklif ve onayda çevrimdışı sensör `409 sensor_offline` ile reddedilir; arayüzde net uyarı ve
   düğme kapalı.
2. Durum makinesi: `dispatched` ve `dispatched_at`, `execution_deadline`, `failure_code`
   (yapısal). Sensöre teslimde `dispatched`; sonuç gelmezse süre aşımı ile `failed(timeout)`.
3. Arka plan süpürmesi (Celery beat, dakikada bir): teslim edilmemiş `pending` ve sonuçsuz
   `dispatched` kayıtlarını kapatır, denetim kaydı ve bildirim yazar (A2, A3).
4. Onay anında canlılık ve yetki yeniden denetimi (A4).
5. Sensör çevrimdışı/çevrimiçi olayları ve bildirimi, arayüzde sensör uyarı bandı (A7).
6. Yerel denetleyici: sensör, denetleyici durumunu kalp atışıyla bildirir; kapalıysa arayüz uyarı
   gösterir (A5). Denetleyiciye yerel oturum belirteci (B3).

**Aşama 2: Güvenlik sıkılaştırması (B1–B8, E2)**
7. Genel hız sınırlama: yol grubu başına kova (alım, yükleme, arama, dışa aktarma), nginx
   `limit_req` ile ikinci katman.
8. "Her uç nokta bir yetki bildirir" testi (route taraması), kural dışı olanlar açık bir izin
   listesinde (B6).
9. Hassas okumaların denetim kaydı (denetim dışa aktarma, kullanıcı listesi) ve isteğe bağlı
   syslog/webhook itme (B7).
10. HSTS ve başlıkların TLS proxy'sinde doğrulanması/eklenmesi (B5).
11. Sensör kimlik bilgisi: parola yerine sensöre özel, kapsamlı ve yenilenebilir anahtar (B2).
    Bu en büyük değişiklik; ayrıca onay istenecek.

**Aşama 3: Arayüz uçtan uca (C1–C3)**
12. Sensör ekleme sihirbazı: anahtarı bir kez göster, kopyala, tek satırlık kurulum komutu,
    kurulum paketi indirme.
13. Sensör sağlık sayfası: sürüm, çevrimdışı süresi, yetenekler, uyarılar.

**Aşama 4: Dayanıklılık (D1–D7)**
14. Kuyruk: boyut/sayı sınırı ve en eskiyi atma politikası, atomik yazım (geçici dosya + yeniden
    adlandırma), bozuk dosyayı karantinaya alma, testler.
15. Geri çekilme ve rastgelelik: üstel backoff + jitter (heartbeat ve boşaltma).
16. Olay düzeyinde idempotency doğrulaması ve testi; sensör işlem izleme ve yeniden başlatma testi.

**Aşama 5: Keşif (bu raporda açık bırakılanlar)**
17. Girdi doğrulama taraması (alım ve yükleme), bağımlılık zafiyet taraması, imaj sertleştirme,
    bulut bağlayıcı sırlarının saklanması; bulgular ayrı raporda.

## 4. Onay gerektiren kararlar

1. Aşama sırası (öneri: 1 → 2 → 4 → 3 → 5).
2. B2'nin (sensör kimlik modeli değişikliği) kapsamı: geriye dönük uyumlu geçiş mi, kesin geçiş mi.
3. A1 çevrimiçi eşiği (öneri 45 sn) ve teslim süresi (öneri 15 dk korunsun, yürütme süresi
   eklensin).
4. Sensör kuyruğu üst sınırı (öneri 500 MB veya 2000 dosya).
5. Her aşama sonunda canlıya alma için ayrı onay mı, tek seferde mi.

## 5. Uygulama durumu (2026-11-15)

| Madde | Durum |
|---|---|
| A1 çevrimdışı sensör | **Yapıldı.** `sensor_offline` (409) teklifte ve onayda; 45 sn eşiği; arayüzde çevrimdışı seçenekler kapalı ve uyarı |
| A2 süpürme | **Yapıldı.** Dakikada bir Celery görevi `sweep_response_actions_task` |
| A3 `dispatched` | **Yapıldı.** Migrasyon 019 (`dispatched_at`, `failure_code`); sonuç gelmezse 5 dk sonra `failed (timeout)` |
| A4 onayda yeniden denetim | **Yapıldı** |
| A5 denetleyici durumu sunucuya | **Yapılmadı.** Eylemi sensör işlemi uygular; denetleyici yalnızca başlat/durdur içindir. Değeri düşük bulundu |
| A6 yapısal hata kodu | **Kısmen:** `failure_code` (`timeout`, `not_delivered`); sensörden gelen serbest metin aynen duruyor |
| A7 | Düzeltme notu yukarıda; arayüzde anlık çevrimiçi/çevrimdışı rozeti eklendi |
| Ek güvenlik bulgusu | Zaman aşımına uğrayan eylem aslında uygulanmış olabilir; bu yüzden `failed (timeout)` ve `dispatched` durumları da "Şimdi kaldır" ile geri alınabilir (sensöre kaldırma emri gider) |
| B1 hız sınırı | **Yapıldı.** Oturum başına, adres başına ve ağır çağrılar (yükleme, denetim dışa aktarma) için; Redis yoksa süreç içi sayaç, Redis erişilemezse engellemez; geliştirmede kapalı. nginx `limit_req` eklenmedi (B5) |
| B2 sensör kimliği | **Yapılmadı** (ayrı onay gerektiriyordu) |
| B3 denetleyici belirteci | **Yapılmadı.** Tarayıcıya belirteci güvenle iletmek bir eşleştirme arayüzü gerektirir; tasarım kararı bekliyor |
| B6 yetki bütünlük testi | **Yapıldı** (`test_api_hardening.py`): açık liste dışında kimlik bağımlılığı olmayan rota testi bozar |
| B7 | **Kısmen:** denetim dışa aktarımı kaydediliyor; syslog/webhook itme yapılmadı |
| C1–C3 | Kayıt ve kimlik bilgisi indirme zaten vardı; çevrimiçi rozeti ve 15 sn yenileme eklendi. Kurulum paketinin arayüzden indirilmesi yapılmadı |
| D1 kuyruk sınırı | **Yapıldı** (2000 dosya, 500 MB; en eski atılır) |
| D2 geri çekilme | **Yapıldı** (kalp atışı ve yükleme için üstel + rastgelelik). **Döngüye bağlantı yalnızca elle okunarak ve derlenerek doğrulandı; ana döngü için otomatik test yok** |
| D3 atomik yazım | **Yapıldı** |
| D4 zehirli dosya | **Yapıldı** (`bad-*` olarak kenara alınır, sonrakiler gönderilir) |
| D5, D6 | **Yapılmadı / incelenmedi** |
| E1 | Çevrimdışı, zaman aşımı, süpürme, kuyruk sınırı, atomiklik, karantina, backoff testleri yazıldı |
| 5. aşama taraması | `pip-audit` (requirements.lock) ve `npm audit` (üretim ve geliştirme): **bilinen zafiyet yok** (tarama anındaki veri tabanına göre). Girdi doğrulama, imaj sertleştirme, bulut sırları: **yapılmadı** |
