# Tespit başarımı değerlendirme çerçevesi

Bu klasör, SentinelAI XDR'ın tespit yöntemlerinin **etiketli veri üzerinde ölçülmesi** için kod ve sonuçları içerir:
kesinlik (precision), duyarlılık (recall), F1 ve yanlış pozitif oranı (FPR), %95 güven aralıklarıyla.
Ürün kodunun parçası değildir (konteynerlere girmez); ama ürünün gerçek tespit mantığını (`backend/app/detection`) kullanır.

Sonuç raporları (Türkçe):

- [`results/RAPOR.md`](results/RAPOR.md): yöntem karşılaştırması, simülasyon üzerinde, tablolar ve grafikler.
- [`results/GERCEK_VERI.md`](results/GERCEK_VERI.md): halka açık gerçek saldırı kayıtlarında kural denemesi (yalnızca duyarlılık).
- [`results/ADAY_KURALLAR.md`](results/ADAY_KURALLAR.md): yavaş saldırılar için üç aday kural, ayrı tohumlarda (`run_candidates.py`).

## Araştırma sorusu

SentinelAI XDR'daki tespit yöntemleri (şeffaf kurallar, basit eşikler, gözetimsiz makine öğrenmesi ve bunların birleşimi) etiketli
bir veri üzerinde saldırı davranışlarını ne kadar doğru yakalıyor ve normal ama şüpheli görünen davranışlarda ne kadar yanlış alarm üretiyor?

## Neler karşılaştırılıyor

| Yöntem | Ne yapar |
|---|---|
| `rules` | Yerleşik 35 kural; içe alım hattıyla aynı değerlendiriciler (`app/detection/evaluate.py`) |
| `suppressed` | Kurallar, ama aynı bilgisayarda en az 3 ayrı pencerede tekrarlanan süreç bulguları rutin sayılıp yok sayılır (bir hipotez; üründe yok) |
| `threshold` | Tüm dönemde 10+ oturum açma hatası veya 20+ farklı hedef port (analistin ilk yazacağı sorgu) |
| `forest` | Isolation Forest, altı özellik, etiketsiz eğitim (projenin isteğe bağlı modeli) |
| `hybrid` | Kural **veya** Isolation Forest |

## Veri: simülatör ve gerçek veri

**Simülatör** (`sentinel_eval/simulate.py`) tohumlu ve tekrarlanabilirdir. Varlıklar kaynak IP, Windows bilgisayarı veya bulut hesabıdır; her varlığın
tek rolü vardır: 11 iyi huylu profilden biri ya da 16 saldırı ailesinden biri. Zor durumlar iki yönde de vardır: saldırıya benzeyen iyi huylu davranışlar
(parolayı unutan kullanıcı, çok kullanıcılı NAT ağ geçidi, zamanlanmış tarayıcı, Office/WMI otomasyonu, Temp'ten kurulum, onaylı bulut değişikliği) ve
eşiklerin altında kalan yavaş saldırılar. **Zor durumların payı** en önemli varsayımdır; bu yüzden `--hard-scale` ile ayarlanır ve iki değerle raporlanır.

**Gerçek veri** için `--dataset` ile JSON Lines dosyası verilir (biçim: `sentinel_eval/datasets.py` başlığı). Her satır bir olaydır ve en az
`event_time`, `event_type`, `entity`, `label` alanlarını taşır (`label`: `benign` veya saldırı ailesi adı). Genel biçim `docs/EVENT_SCHEMA.md` ile aynıdır.
Akış (flow) tabanlı etiketli CSV dosyaları (ör. CICIDS2017) için `convert_flows_csv.py` bu biçime çevirir; **tam tarih ve saat içeren** bir zaman sütunu şarttır
(dakika ve saniyeden ibaret, satırları karışık bir kopya denendi ve reddedildi). Çeviri kuralları ve etiketleme sorumluluğu veri kümesinin belgelerindedir.

Bu depoda **iyi huylu ve saldırı etiketli gerçek bir veri kümesiyle ölçüm yapılmamıştır**.

**Gerçek saldırı kayıtları (yalnızca duyarlılık):** `fetch_otrf.py`, OTRF Security-Datasets deposundan sekiz halka açık Windows saldırı kaydını indirir
(toplam yaklaşık 4,5 MB; yalnızca veri olarak okunur, çalıştırılmaz, SHA-256 doğrulanır). `run_otrf.py`, bu kayıtlardan yalnızca SentinelAI sensörünün topladığı
Güvenlik günlüğü olaylarını dönüştürüp kuralları çalıştırır. Her kayıt için beklenen kural, kayıt çalıştırılmadan önce belgelenmiş tekniğe göre belirlenmiştir.
Kayıtlarda olay başına etiket ve iyi huylu karşılık olmadığından yanlış pozitif oranı bu yolla ölçülemez.

```text
python research/fetch_otrf.py <klasör>
python research/run_otrf.py <klasör> --output-dir research/results
```

## Çalıştırma

Gereksinim: Python 3.12, `numpy`, `scikit-learn` (`backend/requirements-ml.txt`) ve çalışma dizininde `backend/` kaynağı. Docker ile (hiçbir şeyi değiştirmeden):

```text
docker run --rm -v "<proje>:/work:ro" -v "<çıktı>:/out" python:3.12-slim sh -c "pip install -q numpy scikit-learn && cd /work && python -B research/run_evaluation.py --seeds 20 --entities 500 --output-dir /out"
```

Seçenekler: `--seeds` (tohum sayısı), `--entities` (ağ başına varlık), `--prevalence` (saldıran oranı, varsayılan 0,10), `--hard-scale` (ana senaryo, 0,25),
`--stress-scale` (karşılaştırma senaryosu, 1,0), `--contamination` (Isolation Forest, 0,05), `--dataset`, `--output-dir`. 20 tohum ve 500 varlıkla yaklaşık 6–8 dakika sürer.

Çıktılar: `RAPOR.md`, `results.json` (ham sayılar), `figures/*.svg`.

## Testler

`backend/tests/test_research_evaluation.py`: metriklerin elle hesapla uyumu, Wilson aralığı, simülatörün tekrarlanabilirliği ve etiketleri,
her kuralın hedef saldırı ailesini yakalaması, yavaş saldırıların hızlı kural eşiklerinin altında kalması, baskılama mantığı, veri yükleyici ve
küçük bir uçtan uca çalıştırma (scikit-learn varsa).

## Nasıl okunmalı

- **Sentetik sonuç, gerçek dünya oranı değildir.** Simülatörün neyi "normal" ve neyi "saldırı" saydığı yazarların varsayımıdır ve kurallar da aynı kişilerce yazılmıştır;
  kurallar lehine bir yanlılık beklenir. Sonuçlar "bu varsayımlar altında davranış"ı gösterir.
- **Kesinlik saldırgan oranına bağlıdır.** Raporun 6. bölümü, ölçülen duyarlılık ve FPR'den hesaplanmış bir projeksiyondur (ölçüm değil).
- **Eşikler ayarlanmadı.** Kural eşikleri ve Isolation Forest ayarları bu veriye göre seçilmedi; eşik taraması yalnızca ödünleşimi gösterir. Eşiği aynı veride "en iyi" seçmek
  döngüsel (kendi verisinde doğrulama) olurdu; ayrı bir doğrulama veri kümesi gerekir.
- **Etiket birimi varlıktır**, olay değil.
- **Gerçek kayıtlardaki sonuç (5 / 8) küçük bir örnektir;** ıskalanan üçün nedenleri iki veri toplama/kaynağı boşluğu (Sistem 7045 ve Sysmon) ve bir kural darlığıdır; çözümlemeleri `GERCEK_VERI.md` içindedir.
- **Yöntemler eşit veri görmez:** Isolation Forest ve basit eşik yalnızca oturum açma ve ağ sayımlarını görür; kurallar uç nokta ve bulut olaylarını da görür.
