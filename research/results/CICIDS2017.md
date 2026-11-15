# CIC-IDS2017 üzerinde ağ kurallarının ölçümü: akış yönü ön işlemesi (etiketli gerçek veri)

Veri: CIC-IDS2017 akış kayıtları (2.827.677 akış, 17.002 kaynak adresi; 10 adres en az bir saldırı akışı taşıyor). Her akış bir `net.conn` olayıdır, varlık kaynak adrestir. Zaman damgaları 12 saatlik saatten düzeltildi (bkz. `run_cicids_parquet.py`). Kaynak: Sharafaldin, Lashkari, Ghorbani, ICISSP 2018; Hugging Face kopyası `rdpahalavan/CIC-IDS2017`.

## Yöntem

İlk ölçümde yanlış alarmların büyük kısmının akış yönü yapaylığı olduğu görüldü (hedef port, içerideki istemcinin geçici portu). Bu ölçümde **sonucu görmeden belirlenmiş dört ön işleme adayı** denendi: `none` (tüm akışlar), `below1024`, `below32768`, `below49152` (yalnızca hedef portu bu sınırın altında olan akışlar tutulur). Adresler üç kümeye bölündü: eğitim (8.330 adres, 5 saldırgan; yalnızca Isolation Forest için), **doğrulama** (3.571 adres, 2 saldırgan) ve **sınama** (5.101 adres, 3 saldırgan; ilk ölçümdeki sınama kümesiyle aynıdır). Seçim kuralı sonuçlar görülmeden yazıldı: doğrulama kümesinde kural duyarlılığı `none`'ınkinden düşük olmayan adaylar arasında en düşük yanlış pozitif oranlı olan seçilir; eşitlikte listedeki ilk aday. Sınama kümesi seçimden sonra **bir kez** okundu ve yalnızca `none` ile seçilen aday gösterilir.

## Doğrulama kümesi (seçim burada yapıldı)

| Aday | Tutulan akış | Duyarlılık | Yanlış pozitif oranı | TP | FP | FN | TN |
|---|---:|---|---|---:|---:|---:|---:|
| `none` | 2.827.677 | %100,0 [%34,2–%100,0] | %3,8 [%3,3–%4,5] | 2 | 137 | 0 | 3432 |
| `below1024` | 2.200.561 | %100,0 [%34,2–%100,0] | %0,1 [%0,0–%0,2] | 2 | 2 | 0 | 3567 |
| `below32768` | 2.422.751 | %100,0 [%34,2–%100,0] | %0,5 [%0,3–%0,8] | 2 | 18 | 0 | 3551 |
| `below49152` | 2.519.188 | %100,0 [%34,2–%100,0] | %1,1 [%0,8–%1,5] | 2 | 40 | 0 | 3529 |

Seçilen: **`below1024`**.

## Sınama kümesi (bir kez okundu)

### Ön işleme: `none`

| Yöntem | Kesinlik | Duyarlılık | F1 | Yanlış pozitif oranı | TP | FP | FN | TN |
|---|---|---|---|---|---:|---:|---:|---:|
| SentinelAI ağ kuralları (varsayılan açık) | %1,3 [%0,4–%3,6] | %100,0 [%43,9–%100,0] | %2,5 | %4,6 [%4,0–%5,2] | 3 | 234 | 0 | 4864 |
| Ağ kuralları + 3 yavaş saldırı kuralı | %1,2 [%0,4–%3,5] | %100,0 [%43,9–%100,0] | %2,4 | %4,9 [%4,3–%5,5] | 3 | 247 | 0 | 4851 |
| Basit eşik (20+ farklı hedef port) | %0,3 [%0,1–%1,0] | %100,0 [%43,9–%100,0] | %0,7 | %17,1 [%16,1–%18,1] | 3 | 871 | 0 | 4227 |
| Isolation Forest | %1,1 [%0,4–%3,3] | %100,0 [%43,9–%100,0] | %2,3 | %5,1 [%4,5–%5,7] | 3 | 260 | 0 | 4838 |

Tüm adreslerde varsayılan kuralların işaretlediği iyi huylu adresler: iç ağdan 5 / 6, dış adreslerden 733 / 16986.

### Ön işleme: `below1024`

| Yöntem | Kesinlik | Duyarlılık | F1 | Yanlış pozitif oranı | TP | FP | FN | TN |
|---|---|---|---|---|---:|---:|---:|---:|
| SentinelAI ağ kuralları (varsayılan açık) | %50,0 [%18,8–%81,2] | %100,0 [%43,9–%100,0] | %66,7 | %0,1 [%0,0–%0,2] | 3 | 3 | 0 | 5095 |
| Ağ kuralları + 3 yavaş saldırı kuralı | %50,0 [%18,8–%81,2] | %100,0 [%43,9–%100,0] | %66,7 | %0,1 [%0,0–%0,2] | 3 | 3 | 0 | 5095 |
| Basit eşik (20+ farklı hedef port) | %100,0 [%20,6–%100,0] | %33,3 [%6,2–%79,2] | %50,0 | %0,0 [%0,0–%0,1] | 1 | 0 | 2 | 5098 |
| Isolation Forest | %30,0 [%10,8–%60,3] | %100,0 [%43,9–%100,0] | %46,2 | %0,1 [%0,1–%0,3] | 3 | 7 | 0 | 5091 |

Tüm adreslerde varsayılan kuralların işaretlediği iyi huylu adresler: iç ağdan 5 / 6, dış adreslerden 0 / 16986.

## Kural bazında bulgular (tüm adresler)

| Ön işleme | Kural | Saldırgan adres | İyi huylu adres |
|---|---|---:|---:|
| `none` | `port_scan_like` | 10 | 738 |
| `none` | `port_scan_slow` | 7 | 295 |
| `none` | `unusual_conn_volume` | 10 | 206 |
| `below1024` | `unusual_conn_volume` | 9 | 5 |
| `below1024` | `port_scan_like` | 3 | 1 |
| `below1024` | `port_scan_slow` | 2 | 0 |

## Yorum

- **Seçilen ön işleme `below1024`.** Sınama kümesinde ağ kurallarının yanlış pozitif oranı %4,6'dan %0,1'e (234 yanlış alarm yerine 3), kesinlik %1,3'ten %50'ye çıktı; duyarlılık aynı kaldı (3 / 3). Dıştan gelen 16.986 iyi huylu adresin hiçbiri işaretlenmedi (önce 733).
- **Bu, tespit başarımının artması değil, veri kümesindeki yön yapaylığının giderilmesidir.** Kurallar değişmedi; yalnızca kurallara verilen akışlar süzüldü. Ürünün sensörü bağlantıyı başlatan tarafı bildiği için bu süzme gerçek kurulumda uygulanacak bir işlem değildir.
- **Maliyeti var.** Tüm 10 saldırgan adreste `unusual_conn_volume` 9 adrese ateşlendi, `port_scan_like` ise 10'dan 3'e, `port_scan_slow` 7'den 2'ye düştü; basit eşiğin sınama duyarlılığı 3 / 3'ten 1 / 3'e indi. Bunun nedeni tarama akışlarının bir kısmının 1024 üstü portlara gitmesi olabilir; ayrıca denetlenmedi.
- **Seçim zayıf dayanaklıdır.** Doğrulama kümesinde 2 saldırgan vardı ve dört adayın dördü de bunların ikisini yakaladı; seçimi yanlış pozitif oranı belirledi. Sınama kümesinde 3 saldırgan var; kesinlik aralığı %18,8–%81,2.
- 6 iç ağ iyi huylu adresinden 5'i her iki ön işlemede de işaretli kaldı; incelenmedi.

## Sınırlılıklar

- Saldırgan adres yalnızca 10'dur; doğrulama kümesinde çok azı kalır, bu yüzden **seçim istatistiksel olarak zayıftır** ve sınama kümesinde 3 saldırgan vardır. Aralıklar geniştir; sonuç bir sıralama kanıtı değil, bir yön göstergesidir.
- Port sınırına göre süzmek yönü tahmin eder: uzak sunucunun hizmet portuna giden gerçek saldırı akışları da (ör. yüksek portlu hizmetlere tarama) elenebilir. Süzme, ürünün sensörünün gerçekte ürettiği akışlara uygulanacak bir işleme değildir; bu, veri kümesinin yapaylığını gidermeye yönelik bir ön işlemdir.
- Duyarlılık adres düzeyindedir ve atıf değildir. Akış verisinde oturum açma, süreç ve bulut olayı yoktur; yalnızca ağ kuralları denenebildi.
- Bu veri kümesi tek bir laboratuvar ağında, beş günde toplandı; etiket ve akış üretimi hataları bildirilmiştir (Engelen ve ark., 2021). Saat düzeltmesi (12 saatlik saatten) bir varsayımdır.
- Kural eşikleri değiştirilmedi; yalnızca girdi akışları süzüldü.
