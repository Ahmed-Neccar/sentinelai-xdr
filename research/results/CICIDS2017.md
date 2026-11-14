# CIC-IDS2017 üzerinde ağ kurallarının ölçümü (etiketli gerçek veri)

Veri: CIC-IDS2017 akış kayıtları (2.827.677 akış, 17.002 kaynak adresi; 10 adres en az bir saldırı akışı taşıyor). Her akış bir `net.conn` olayıdır, varlık kaynak adrestir. Zaman damgaları 12 saatlik saatten düzeltildi (bkz. `run_cicids_parquet.py`). Kaynak: Sharafaldin, Lashkari, Ghorbani, ICISSP 2018; Hugging Face kopyası `rdpahalavan/CIC-IDS2017`.

Değerlendirme kümesi: adreslerin rastgele %30'u (5.101 adres, 3 saldırgan). **Saldırgan sayısı çok küçüktür; aralıklar geniştir.**

| Yöntem | Kesinlik | Duyarlılık | F1 | Yanlış pozitif oranı | TP | FP | FN | TN |
|---|---|---|---|---|---:|---:|---:|---:|
| SentinelAI ağ kuralları (varsayılan açık) | %1,3 [%0,4–%3,6] | %100,0 [%43,9–%100,0] | %2,5 | %4,6 [%4,0–%5,2] | 3 | 234 | 0 | 4864 |
| Ağ kuralları + 3 yavaş saldırı kuralı | %1,2 [%0,4–%3,5] | %100,0 [%43,9–%100,0] | %2,4 | %4,9 [%4,3–%5,5] | 3 | 247 | 0 | 4851 |
| Basit eşik (20+ farklı hedef port) | %0,3 [%0,1–%1,0] | %100,0 [%43,9–%100,0] | %0,7 | %17,1 [%16,1–%18,1] | 3 | 871 | 0 | 4227 |
| Isolation Forest | %1,1 [%0,4–%3,2] | %100,0 [%43,9–%100,0] | %2,2 | %5,3 [%4,7–%5,9] | 3 | 268 | 0 | 4830 |

## Saldırgan adreslerin etiketleri

| Adres türü | Akış etiketleri |
|---|---|
| dış / NAT | DoS Hulk: 230123, PortScan: 158804, DDoS: 128022, DoS GoldenEye: 10293, FTP-Patator: 7935, SSH-Patator: 5897, DoS slowloris: 5796, DoS Slowhttptest: 5499, Web Attack – Brute Force: 1507, Web Attack – XSS: 652, Web Attack – Sql Injection: 21, Heartbleed: 11 |
| dış / NAT | Bot: 701 |
| iç ağ (192.168.10.x) | Bot: 366 |
| iç ağ (192.168.10.x) | Bot: 271, Infiltration: 36 |
| iç ağ (192.168.10.x) | Bot: 226 |
| iç ağ (192.168.10.x) | Bot: 209 |
| iç ağ (192.168.10.x) | Bot: 179 |
| iç ağ (192.168.10.x) | DDoS: 3 |
| iç ağ (192.168.10.x) | Bot: 2 |
| iç ağ (192.168.10.x) | Bot: 2 |

## Kural bazında bulgular (tüm adresler)

| Kural | Saldırgan adres | İyi huylu adres |
|---|---:|---:|
| `port_scan_like` | 10 | 738 |
| `port_scan_slow` | 7 | 295 |
| `unusual_conn_volume` | 10 | 206 |

## Nasıl yorumlanmalı

- **Yanlış alarmların büyük kısmı akış yönü yapaylığıdır (ayrıca kontrol edildi).** Bu veri kümesinde akışlar çift yönlüdür ve bazı kayıtlarda "kaynak" uzak sunucudur; o zaman "hedef port" içerideki istemcinin geçici (ephemeral) portudur. İyi huylu, dıştan içe akışların %89,6'sında hedef port 32768 veya üstüdür; içten içe akışlarda bu oran %2,4, içten dışa akışlarda %4,6'dır. Tüm gün boyunca 12 veya daha fazla farklı hedef porta sahip iyi huylu dış adres sayısı 4.639'dur (16.988 dış adresten) ve bunların farklı portlarının ortalama %88,4'ü geçici portlardır. `port_scan_like` ve `unusual_conn_volume` kaynağın bağlantıyı başlatan taraf ve hedef portun hizmet portu olduğunu varsayar; bu varsayım burada bozuluyor. Yönü düzelten bir ön işleme (ör. yalnızca bilinen hizmet portlarına giden akışlar) ayrıca denenmedi; denenseydi bu veriye göre ayar olurdu.
- **Duyarlılık adres düzeyindedir ve atıf değildir.** Bir adres saldırı etiketli bir akış taşıyorsa saldırgan sayılır; kural, o adresin iyi huylu akışlarından da ateşlenmiş olabilir. Saldırgan adres yalnızca 10 olduğu için (değerlendirme kümesinde 3) duyarlılık aralığı çok geniştir (%43,9–%100).
- **Kesinlik çok düşük çıkar** çünkü 17 bin adrese karşı 10 saldırgan vardır (saldıran oranı %0,06); düşük saldıran oranında kesinliğin düşeceği, simülasyon raporundaki projeksiyonla uyumludur.
- Basit eşik ve Isolation Forest da aynı yön yapaylığından etkilenir; bu karşılaştırma yöntemlerin sıralaması hakkında güçlü bir sonuç vermez.

Varsayılan kuralların işaretlediği iyi huylu adresler: iç ağdan 5 / 6, dış adreslerden 733 / 16986.

## Sınırlılıklar

- Akış verisinde oturum açma, süreç ve bulut olayı yoktur; yalnızca ağ kuralları denenebildi. SSH-Patator ve FTP-Patator kaba kuvvet saldırılarıdır ama akışlarda başarısız oturum açma olayı olmadığı için oturum açma kuralları onları göremez.
- Bu veri kümesi tek bir laboratuvar ağında, beş günde, bilinen bir saldırgan kümesiyle toplandı; saldırgan adres sayısı çok az (tek bir NAT adresi birçok saldırı ailesini taşıyor) ve istatistiksel güç düşüktür.
- Eşikler bu veriye göre ayarlanmadı. Zaman damgaları dakika veya saniye çözünürlüğündedir; saat düzeltmesi (12 saatlik saatten) bir varsayımdır.
- Bilinen eleştiriler: CIC-IDS2017'nin etiketlerinde ve akış üretiminde hatalar bildirilmiştir (Engelen ve ark., 2021); bu kopya düzeltilmiş sürüm olmayabilir.
