# SentinelAI XDR: başvuru için teknik özet (taslak)

Bu metin, proje deposundaki kayıtlara (`docs/STATUS.md`, `research/results/`) dayanır ve başvuru metni yazılırken kaynak olarak kullanılmak üzere hazırlanmıştır.
Her sayı bir dosyaya ve bir komuta bağlıdır; sonuçlar ve sınırlılıklar bilerek açık yazılmıştır. Son bölüm, değerlendiricinin sorabileceği iddiaları ve bu depodaki karşılığını verir.

## 1. Problem

Küçük ve orta ölçekli kurumlarda uç nokta, ağ ve bulut telemetrisi ayrı araçlarda durur; tespit kuralları kurumun kendi verisinde ölçülmeden çalıştırılır ve
analist yanlış alarm oranını bilmez. Tespit yöntemlerinin başarımı çoğu zaman satıcı beyanına dayanır; kendi kurulumunda, tekrarlanabilir biçimde ölçen açık bir çerçeve azdır.

## 2. Amaç

(1) Tek sunucuda çalışan, şeffaf kural tabanlı bir XDR prototipi geliştirmek (toplama, tespit, vaka yönetimi, onaylı müdahale);
(2) tespit yöntemlerini etiketli veri üzerinde **kesinlik, duyarlılık, F1 ve yanlış pozitif oranı** ile, güven aralıklarıyla ve zor durumlar dahil ölçen tekrarlanabilir bir değerlendirme çerçevesi sunmak;
(3) kural tabanlı, eşik tabanlı ve gözetimsiz makine öğrenmesi yöntemlerini aynı veri üzerinde karşılaştırmak.

## 3. Geliştirilen sistem (mevcut durum)

- **Toplama:** Windows sensörü (ağ başlıkları, Güvenlik günlüğü olayları), AWS CloudTrail ve Azure etkinlik günlüğü (salt okunur), dosya içe aktarımı.
- **Tespit:** 38 sürümlü kural (35 açık, 3 deneysel kapalı), kanıt bağlantılı bulgular, vakalara gruplama; isteğe bağlı Isolation Forest.
- **Müdahale:** İki yönetici onayıyla, süreli ve sensörün kendi üzerinde uyguladığı üç eylem (IP engelleme, ağdan yalıtma, yerel hesap kapatma); tümü denetlenir.
- **Güvenlik ve işletim:** PostgreSQL satır düzeyi güvenlikle kiracı izolasyonu, MFA, Microsoft Entra ile tek oturum açma, şifreli yedekler, üretim kipine geçiş betikleri, salt-okunur konteynerler.
- **Doğrulama düzeyi:** 250'den fazla otomatik backend testi, 67 sensör ve 13 arayüz testi; canlıda tek bir laboratuvar bilgisayarında denendi.

Sistem bir **laboratuvar prototipidir**: tek bilgisayarda çalışır, bağımsız güvenlik denetiminden geçmemiştir ve gerçek bir kurumda üretim kullanımı için hazır değildir.

## 4. Değerlendirme protokolü

- **Etiket birimi:** varlık (kaynak IP, Windows bilgisayarı veya bulut hesabı). Bir yöntem, varlığın olaylarına dayanan bir bulgu ürettiyse onu saldırgan olarak işaretlemiş sayılır.
- **Veri:** tohumlu simülatör; 11 iyi huylu profil, 16 saldırı ailesi, iki yönde zor durum (saldırıya benzeyen iyi huylu davranışlar; eşiklerin altında kalan yavaş saldırılar).
  Zor durumların payı ayrı bir parametredir ve iki değerle raporlanır (%14 ve %39).
- **Yöntemler:** yerleşik kurallar (içe alım hattıyla aynı değerlendiriciler), basit eşik, Isolation Forest, kural veya Isolation Forest.
- **İstatistik:** 20 bağımsız tohum, havuzlanmış sayılar, %95 Wilson aralığı; Isolation Forest %70 etiketsiz eğitim, %30 değerlendirme.
- **Gerçek veri:** halka açık Windows saldırı kayıtları (OTRF Security-Datasets), beklenen kural kayıt çalıştırılmadan önce belirlenerek; yalnızca duyarlılık ölçülür.
- **Tekrar üretilebilirlik:** `python research/run_evaluation.py`, `research/fetch_otrf.py`, `research/run_otrf.py`; tüm sayılar `research/results/` altında.

## 5. Bulgular

Simülasyon (ana senaryo, %10 saldıran, 20 tohum × 500 varlık; `research/results/RAPOR.md`):

| Yöntem | Kesinlik | Duyarlılık | F1 | Yanlış pozitif oranı |
|---|---|---|---|---|
| Yerleşik kurallar | %37,5 | %78,4 | %50,7 | %13,4 |
| Basit eşik (taban çizgi) | %63,2 | %46,4 | %53,5 | %2,8 |
| Isolation Forest | %35,0 | %17,3 | %23,1 | %3,3 |
| Kural veya Isolation Forest | %37,4 | %81,7 | %51,3 | %14,0 |

- Kurallar hızlı saldırıları ve uç nokta, bulut ve kalıcılık olaylarını yakalar; basit eşik bunları göremez.
- **Yavaş saldırıların tamamı** (yavaş kaba kuvvet, yavaş parola püskürtme, yavaş port taraması) mevcut kısa pencereli kurallarca ıskalanır. Bir saatlik pencereli üç deneysel kural,
  ayrı tohumlarda %77–100 duyarlılık ve %0,9–5 yanlış pozitif oranı verdi (`ADAY_KURALLAR.md`); kapalı gelir.
- Meşru otomasyon, çok kullanıcılı NAT ağ geçidi, zamanlanmış tarayıcı ve parolasını unutan kullanıcıda yanlış alarm yüksektir (zor durumlar %39'a çıkınca kuralların yanlış pozitif oranı %38).
- Saldıran oranı %1 veya altında olduğunda tüm yöntemlerin kesinliği düşüktür (ölçülen duyarlılık ve yanlış pozitif oranından hesaplanmış projeksiyon).
- Gerçek kayıtlar (`GERCEK_VERI.md`): sekiz kaydın beşinde beklenen kural ateşlendi. Üç ıskalama üç farklı nedene dayanır: Sistem günlüğündeki 7045 olayı toplanmıyor, bir teknik yalnızca Sysmon'da görünüyor, bir WMI kuralı fazla dar.

## 6. Sınırlılıklar

- Sonuçların ana kısmı **sentetik veriden** gelir; neyin "normal" ve neyin "saldırı" olduğunu simülatörü yazanlar tanımlamıştır ve kurallar aynı kişilerce yazılmıştır (kurallar lehine yanlılık beklenir).
- Kural eşikleri ve model ayarları bu veriye göre **seçilmemiştir**; ayrı bir doğrulama kümesinde eşik seçimi yapılmamıştır.
- **İyi huylu ve saldırı etiketli gerçek bir veri kümesiyle ölçüm yoktur.** Bir kamu veri kümesi denendi ve reddedildi: kopyada zaman damgası yalnızca dakika ve saniyeden oluşuyor ve satırlar karışık sıradaydı (pencereli kurallar anlamsız olurdu) ve yalnızca 27 kaynak adresi vardı.
- Makine öğrenmesi bileşeni (Isolation Forest, altı özellik) **zayıf** çıktı ve projenin ana katkısı değildir. Gözetimli bir model denenmemiştir.
- Tespit yalnızca bu sensörün topladığı veri kaynaklarına bağlıdır (Güvenlik günlüğü; Sysmon ve Sistem günlüğü okunmaz).

## 7. Önerilen iş planı (taslak; başvuru sahibi karar verir)

1. İyi huylu ve saldırı etiketli, tam zaman damgalı bir kamu veri kümesi seçmek; `research/convert_flows_csv.py` ile dönüştürüp aynı protokolle ölçmek.
2. Eşikleri ayrı bir doğrulama kümesinde seçmek; sonucu görmemiş bir sınama kümesinde bildirmek.
3. Gözetimli bir modeli (ör. ağaç tabanlı) etiketli veride eğitip kural ve eşikle karşılaştırmak.
4. Sensörde Sistem günlüğü 7045 ve Sysmon okumasını eklemek ve etkisini aynı protokolle ölçmek.
5. İkinci bir gerçek bilgisayarla uzak sensör ve müdahale doğrulaması.

## 8. Değerlendiricinin sorabileceği iddialar ve bu depodaki karşılığı

| İddia | Karşılık |
|---|---|
| "Yapay zekâ ile tehdit tespiti" | Ana tespit kurallardır. Makine öğrenmesi bileşeni ölçüldü ve zayıf çıktı; bunu açıkça yazın. |
| "Yüksek doğruluk" | Yok. Simülasyonda kurallar F1 %50,7; yanlış pozitif oranı %13,4. Doğruluk iddiasında bulunmayın. |
| "Gerçek veriyle doğrulandı" | Kısmen: 8 gerçek saldırı kaydında duyarlılık (5/8). Yanlış alarm gerçek veride ölçülmedi. |
| "Üretime hazır" | Hayır. Laboratuvar prototipi. |
| "Özgün katkı" | Savunulabilir olan: kendi tespit hattını zor durumlarla, güven aralıklarıyla ve açık sınırlılıklarla ölçen tekrarlanabilir çerçeve ve onun bulguları (ör. yavaş saldırı boşluğu). |
