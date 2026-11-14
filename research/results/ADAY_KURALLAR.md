# Yavaş saldırılar için aday kurallar

Ana değerlendirme (RAPOR.md), 5 ve 10 dakikalık pencerelerin **her yavaş saldırıyı ıskaladığını** gösterdi (yavaş kaba kuvvet, yavaş parola püskürtme, yavaş port taraması). Bu sayfa, bu boşluğu kapatmak için yazılan 1 saatlik pencereli üç adayı ölçer.

**Ölçüm ayrı tohumlarda yapıldı** (1000–1019; ana değerlendirmede 0–19 kullanıldı) ve iki zorluk senaryosunda tekrarlandı; adaylar, açığı gösteren veriye göre ayarlanmış olmasın diye eşikler ayrıca aranmadı. Yine de açık yavaş saldırı ailelerinin tanımına göre yazıldığı için döngüsellik vardır.

| Aday | Senaryo | Yavaş saldırıda duyarlılık | Hedef ailelerde duyarlılık | Yanlış pozitif oranı |
|---|---|---:|---:|---|
| `auth_bruteforce_username_slow` | ana (zor durumlar az) | %100,0 | %100,0 | %1,5 [%1,3–%1,8] |
| `password_spray_slow` | ana (zor durumlar az) | %76,7 | %88,3 | %1,3 [%1,1–%1,5] |
| `port_scan_slow` | ana (zor durumlar az) | %83,3 | %91,7 | %0,9 [%0,7–%1,1] |
| `auth_bruteforce_username_slow` | stres (zor durumlar çok) | %100,0 | %100,0 | %5,0 [%4,6–%5,5] |
| `password_spray_slow` | stres (zor durumlar çok) | %80,0 | %90,0 | %3,8 [%3,4–%4,2] |
| `port_scan_slow` | stres (zor durumlar çok) | %81,7 | %90,8 | %2,5 [%2,2–%2,8] |

## Karar

Üç kural `BUILTIN_RULES` içine **varsayılan olarak kapalı** eklendi (`default_enabled: False`); Kurallar sayfasından bir yönetici açabilir. Simülasyon, gerçek ağdaki gürültüyü içermez (örneğin sürekli eski parolayla yeniden deneyen bir telefon), bu yüzden gerçek veride yanlış alarm beklenir ve açılmadan önce kendi ağınızda bir süre izlenmelidir.

## Sınırlılıklar

- Sentetik veri; yavaş saldırının “yavaş” tanımı simülatörü yazanlarındır.
- Kurallar sabit, saat sınırlarına hizalı 1 saatlik pencereler kullanır; pencere sınırını aşan bir saldırı iki parçaya bölünür.
- Yalnızca her aday kendi başına ölçüldü; birlikte çalıştıklarında çakışan bulgular ve vaka sayısı ölçülmedi.
