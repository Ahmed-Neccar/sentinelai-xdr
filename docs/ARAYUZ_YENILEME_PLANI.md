# Arayüz yenileme planı: "Crimson Prism" SOC komuta merkezi

Tarih: 2026-11-15. Durum: **plan; onaya sunuldu, hiçbir kod yazılmadı.**
Referans görsel: sizin ilettiğiniz tasarım (bento kartlar, kadran, açılır bulgu satırları, etkinlik
akışı). Görseldeki yazılar bozuk üretilmiş; yalnızca yerleşim ve his için referans alındı.

## 0. Önce bilinmesi gerekenler (kısıtlar ve dürüst riskler)

1. **`App.tsx` tek dosya, ~105 KB, 38 işlev.** Daha önce toptan yeniden biçimlendirme denenmiş ve
   paket aynı çıkmadığı için bırakılmıştı. Bu yüzden plan **"boğma" (strangler) yöntemidir**: yeni
   yapı yanına kurulur, sayfalar tek tek taşınır, eski kod sayfa taşındıkça silinir. Her adımda
   uygulama çalışır halde kalır.
2. **React Bits bir npm paketi değil;** bileşenleri projeye kopyalanan bir koleksiyon. Spotlight ve
   CountUp gibi parçaları, lisansını kontrol edip kendi küçük bileşenlerimiz olarak yazacağım
   (GSAP/saf CSS ile). Kopyalama yerine sıfırdan yazmak bağımlılığı ve yabancı kodu azaltır.
3. **Yazı tipleri CSP yüzünden kendi sunucumuzdan sunulmalı.** `default-src 'self'` Google Fonts'u
   engeller. Çözüm: `@fontsource-variable/outfit` (veya Plus Jakarta Sans) ve
   `@fontsource/jetbrains-mono` paketleri, Vite ile paketlenir; dış istek yok. (Bugün adı geçen
   DM Sans/Manrope/DM Mono hiç yüklenmiyordu; bu aynı kökten bir hatayı da kalıcı çözer.)
4. **MITRE ATT&CK verisi seyrek.** Alan (`mitre`) var ve arayüze iletiliyor, ama yerleşik
   kuralların çoğunda boş (`[]`). Rozetler ancak kural içeriği doldurulursa dolu görünür. Planın
   bir adımı kural eşlemelerini tamamlamak (bu bir içerik işi, kod değil).
5. **Çekmecenin sekmeleri mevcut veriyle sınırlı.** Bulgu detay ucu `evidence_events` döndürüyor
   (zaman, tür, IP, port, öznitelikler). "Adli Zaman Çizelgesi" ve "Ham JSON" tam karşılanır;
   "Süreç & Ağ Akışı" yalnızca olayların taşıdığı süreç/ağ öznitelikleri kadar zengin olur.
   Zengin süreç ağacı için backend'de yeni bir alan gerekir (kapsam dışı, ayrı karar).
6. **Üç tema (koyu, açık, yüksek kontrast) bugün var.** Yeni tasarım koyu temaya göre. Karar:
   açık/yüksek kontrast temaları korunsun mu, yoksa yeniden tasarım sonrasına mı bırakılsın.
7. **Erişilebilirlik ve performans sınırları:** `prefers-reduced-motion` açıkken tüm animasyonlar
   kapanır; buzlu cam (`backdrop-filter`) pahalıdır, yalnızca üst düzey kartlarda kullanılır, tablo
   satırlarında kullanılmaz; renk kontrastı (metin/zemin) WCAG AA için ölçülür.
8. **Türkçe/İngilizce:** Mevcut `translate()` ve yedek `autoTranslate` korunur; yeni her metin
   `i18n.ts`'e eklenir. Yeni bileşenler çeviri testlerinden geçer.
9. **Gerçek hayattaki sayılar:** Genel Bakış'taki "Tehdit Nabzı", kadran ve zaman çizelgesi gerçek
   verilerden beslenir; mockup'taki değerler (26.152, 112...) örnektir.

## 1. Tasarım sistemi (tokenlar)

`src/design/tokens.css` içinde CSS değişkenleri; tüm bileşenler yalnızca bunları kullanır.

| Token | Değer |
|---|---|
| `--bg` | `#060818` + radyal radar/grid dokusu (CSS, ek görsel yok) |
| `--surface` | `rgba(255,255,255,.03)`, `backdrop-filter: blur(12px)` |
| `--border` | `rgba(139,92,246,.18)` |
| `--accent` | `#8B5CF6` (indigo geçişi `#6366F1`) |
| `--ok` / `--warn` / `--crit` | `#10B981` / `#F59E0B` / `#F43F5E` |
| Başlık/metrik fontu | Outfit (değişken) |
| Mono (IP, hash, port, log) | JetBrains Mono |

Önem renkleri (düşük/orta/yüksek/kritik) tek bir `severity.ts` haritasından gelir; renk körlüğü
için her rozette ikon ve metin de bulunur (yalnızca renge güvenilmez).

## 2. Klasör yapısı

```
frontend/src/
  app/            AppShell (kenar çubuğu, üst bar, sayfa alanı), yönlendirme, oturum
  design/         tokens.css, severity.ts, motion.ts (azaltılmış hareket kontrolü)
  components/
    ui/           Button, Badge, Card(Glass), Tabs, Modal, Drawer, Accordion, Stepper,
                  Table, EmptyState, Skeleton, Toast
    viz/          RiskGauge (GSAP), CountUp, Pulse (sensör nabzı), Spotlight, MitreBadge,
                  SeverityPill, Sparkline
  features/
    overview/     BentoGrid, ThreatPulse, GroupedFindings, SensorHealth, RecentActions
    detections/   DetectionList, DetectionRow(accordion), ForensicDrawer (4 sekme)
    cases/        CaseList, CaseDrawer, ResponseLifecycle (adım çubuğu)
    sensors/      SensorList, EnrollModal, RevokeDialog, SensorCard (izolasyon kilidi)
    (events, hosts, discovery, ingestion, connectors, notifications, users, rules,
     audit, settings: mevcut sayfalar yeni bileşenlere taşınır)
  services/
    http.ts       tek istemci: jeton, yenileme, oturum kaybı, hata eşleme, istek iptali
    sensors.ts  responses.ts  detections.ts  cases.ts  hosts.ts  identity.ts  audit.ts ...
  i18n.ts  autoTranslate.ts  (mevcut, korunur)
```

## 3. API katmanı (istek 4)

- `App.tsx` içindeki `api()` ve `sensorControl()` `services/http.ts` ve `services/controller.ts`
  olarak çıkarılır; **davranış aynı kalır** (jeton, 401'de yenileme, oturum bitince giriş
  sayfası). İlk aşamada yalnızca taşınır, görünüm değişmez; mevcut testler korunur.
- Her alan için tipli bir adaptör (`sensors.list()`, `responses.approve(id)`...). Bileşenlerde
  doğrudan `fetch` kalmaz; bunu bir test ve bir lint kuralı (yasak `fetch(` deseni) zorlar.
- Eksik olanlar için temiz adaptör: bugün backend'de karşılığı olmayan bir şey (ör. sensör sağlık
  geçmişi) arayüzde `NotAvailable` durumuyla gösterilir, sahte veri uydurulmaz.

## 4. Sayfa hiyerarşisi

- **Genel Bakış (bento):** Tehdit Nabzı & Risk Kadranı (olay hızı, açık bulgu skoru), Kategorize
  Edilmiş Bulgular (önem/kategoriye göre gruplu, satır içi açılır), Canlı Sensör Sağlığı
  (çevrimiçi/çevrimdışı, son sinyal, nabız halkası), Son Müdahale Aksiyonları (durum çubuğuyla).
- **Tespitler / Vakalar:** liste → satır içi özet kartı (accordion) → "Detaylı İncele" ile
  sağdan **Adli İnceleme Çekmecesi**; sekmeler: Özet & Risk Skoru → Adli Zaman Çizelgesi →
  Süreç & Ağ Akışı → Ham JSON/Log. Çekmece adresi `#/detections/<id>?tab=timeline` biçiminde
  (bağlantı paylaşılabilir, geri düğmesi çalışır).
- **Sensörler:** kart ızgarası; "Yeni Sensör Kaydet / Anahtar Üret" modalı (anahtar bir kez
  gösterilir, kopyala/indir), tek tıkla "Yetkiyi İptal Et" onayı; çevrimdışı ve izole edilmiş
  durum rozetleri.
- **Müdahale yaşam döngüsü:** `proposed → approved → dispatched → executed / failed` adım çubuğu
  (backend durumları **zaten var**: `proposed, approved, pending, dispatched, applied, refused,
  failed, removal_pending, removed, cancelled`; bunlar 5 adıma eşlenir). Hedef sensör çevrimdışıysa
  "Teklif Et" kilitlenir ve nedeni gösterilir (backend zaten `sensor_offline` ile reddediyor;
  arayüz bunu önceden gösterir). Host izolasyonu etkinken cihaz kartında kırmızı kalkan.
- **Diğer sayfalar** (Olaylar, Cihazlar, Ağ keşfi, Veri alımı, Bulut, Bildirimler, Kullanıcılar,
  Kurallar, Denetim, Ayarlar): aynı bileşenlerle yeniden giydirilir; davranış değişmez.

## 5. Animasyon kuralları

- **GSAP:** çekmece geçişi, kadran dolumu, sensör nabzı, izolasyon kilidi animasyonu. Her
  zaman `gsap.context` ile temizlenir; `prefers-reduced-motion`'da anında son duruma atlar.
- **CountUp, Spotlight, grid dokusu:** yalnızca üst metrikler ve kategori kartlarında; veri
  tablolarında sürekli hareket yok.
- **Lenis:** global `window`'a **bağlanmaz**. Yalnızca "Tehdit Özeti / Vaka Raporu" okuma
  kapsayıcısında, o kapsayıcının kendi elemanına bağlı örnek olarak; çekmece, kenar çubuğu ve
  olay akışı yerel kaydırmada kalır. Kapsayıcı kapanınca `destroy()` çağrılır.
- Bütçe: ek paket boyutu hedefi ≤ 90 KB gzip (GSAP çekirdek + Lenis + yazı tipleri hariç);
  yazı tipleri alt kümeli (latin + latin-ext, Türkçe karakterler için) yüklenir.

## 6. Paketler

`gsap`, `lenis`, `@fontsource-variable/outfit`, `@fontsource/jetbrains-mono`. Mevcut:
`lucide-react`. Yönlendirme için `react-router` **eklenmez**; küçük bir `#/` karma yönlendirici
yazılır (bugün yönlendirme yok, tek `section` durumu var). `npm audit` her eklemeden sonra
çalıştırılır. Kurulum için yeni paket indirme onayınız bu plan onayına dahil sayılacaktır.

## 7. Uygulama aşamaları (her biri ayrı commit, sonunda test ve tarayıcı denetimi)

0. **Temel:** tokenlar, yazı tipleri, `services/http.ts` çıkarımı (görünüm aynı), AppShell,
   hash yönlendirici. Mevcut 25 test geçmeli.
1. **Genel Bakış** (bento, kadran, CountUp, nabız).
2. **Tespitler + Adli Çekmece** (accordion, 4 sekme, MITRE rozetleri, kural eşleme içeriği).
3. **Vakalar + Müdahale yaşam döngüsü çubuğu** ve kilit uyarısı.
4. **Sensörler** (kayıt modalı, iptal onayı, sağlık kartı, izolasyon animasyonu).
5. **Kalan sayfaların yeniden giydirilmesi.**
6. **Cila:** erişilebilirlik taraması, azaltılmış hareket, kontrast ölçümü, performans (düşük
   donanımda kare hızı), Türkçe tam geçiş, açık/yüksek kontrast temaların kararı.

Her aşamada: bileşen testleri (Vitest), tarayıcıda gerçek gezinme (masaüstü + 375 px), `npm run
build`, çeviri testi; canlıya alma her aşama sonunda **sizin onayınızla** ve yedekten sonra.

## 8. Onayınızı bekleyen kararlar

1. **Yazı tipi:** Outfit mi, Plus Jakarta Sans mı? (Öneri: Outfit; Türkçe karakter desteği
   geniş, değişken sürümü küçük.)
2. **Açık ve yüksek kontrast temalar** korunsun mu, sonraya mı bırakılsın? (Öneri: Aşama 6'da
   yeniden uyarla; o zamana kadar koyu varsayılan.)
3. **Hash yönlendirici** ile paylaşılabilir bağlantılar: onay?
4. **MITRE eşleme içeriği** (kurallara teknik kimlikleri ekleme) bu kapsama dahil mi?
5. **"Süreç & Ağ Akışı" sekmesi** mevcut olay özniteliklerine göre mi yapılsın, yoksa backend'e
   süreç ağacı alanı eklemek ayrı bir iş olarak planlansın mı?
6. **Paket boyutu bütçesi** (≤ 90 KB gzip) kabul mü?
7. **Aşama sırası** (0→1→2→3→4→5→6) uygun mu?
