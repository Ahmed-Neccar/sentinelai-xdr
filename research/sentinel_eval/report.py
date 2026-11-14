"""Turns the measured results into a Turkish Markdown report and three SVG figures."""

from __future__ import annotations

import math
from html import escape

METHOD_LABELS = {
    "rules": "SentinelAI kuralları",
    "suppressed": "Kurallar + tekrar baskılama",
    "threshold": "Basit eşik (taban çizgi)",
    "forest": "Isolation Forest",
    "hybrid": "Kural veya Isolation Forest",
}
METHOD_COLORS = {"rules": "#1f5fbf", "suppressed": "#6f42c1", "threshold": "#8a8f98", "forest": "#c47a00", "hybrid": "#1b7a46"}

ATTACK_LABELS = {
    "brute_force_fast": "Hızlı kaba kuvvet (tek hesap)",
    "brute_force_then_success": "Kaba kuvvet ve ardından başarı",
    "slow_brute_force": "Yavaş kaba kuvvet (kaçınmacı)",
    "password_spray": "Parola püskürtme",
    "slow_spray": "Yavaş parola püskürtme (kaçınmacı)",
    "port_scan_fast": "Hızlı port taraması",
    "port_scan_slow": "Yavaş port taraması (kaçınmacı)",
    "lateral_sweep": "Yanal hareket taraması (SMB)",
    "dns_tunnel_like": "DNS tüneline benzer yoğunluk",
    "office_macro_powershell": "Office makrosundan PowerShell",
    "wmi_execution": "WMI ile komut çalıştırma",
    "script_host_shell": "Betik ana sürecinden kabuk",
    "dropped_binary": "Geçici klasörden çalıştırılan program",
    "persistence_or_tampering": "Kalıcılık / günlük silme / hesap değişikliği",
    "cloud_defense_evasion": "Bulutta günlük kapatma / ağ kuralı",
    "cloud_iam_abuse": "Bulutta kimlik/erişim ilkesi kötüye kullanımı",
}
ROLE_LABELS = {
    "workstation": "Sıradan iş istasyonu",
    "forgetful_user": "Parolayı unutan kullanıcı",
    "server": "Sunucu",
    "nat_gateway": "NAT ağ geçidi (çok kullanıcılı)",
    "scheduled_scanner": "Zamanlanmış güvenlik tarayıcısı",
    "dns_resolver": "DNS çözümleyici",
    "ordinary_endpoint": "Sıradan uç nokta (süreçler)",
    "admin_automation": "Yönetici otomasyonu (Office/WMI/betik)",
    "installer_endpoint": "Kurulum programı (Temp/İndirilenler)",
    "approved_cloud_change": "Onaylı bulut değişikliği",
    "cloud_reader": "Bulut salt okuma",
}


def pct(value: float | None) -> str:
    return "-" if value is None else f"%{value * 100:.1f}".replace(".", ",")


def pct_ci(value: float | None, ci: list[float] | None) -> str:
    if value is None:
        return "-"
    if not ci:
        return pct(value)
    return f"{pct(value)} [{pct(ci[0])}–{pct(ci[1])}]"


# -- figures ----------------------------------------------------------------------------------
def _svg(width: int, height: int, body: str) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" '
        f'height="{height}" font-family="Segoe UI, Arial, sans-serif" font-size="12">'
        f'<rect width="{width}" height="{height}" fill="#ffffff"/>{body}</svg>'
    )


def bar_chart(result: dict) -> str:
    metrics = (("precision", "Kesinlik"), ("recall", "Duyarlılık"), ("f1", "F1"))
    width, height, left, top, bottom = 760, 380, 60, 40, 60
    plot_w, plot_h = width - left - 20, height - top - bottom
    body = [f'<text x="{left}" y="22" font-size="14" font-weight="600">Yöntemlerin başarımı (sentetik veri, %95 güven aralıklı)</text>']
    for tick in range(0, 101, 20):
        y = top + plot_h * (1 - tick / 100)
        body.append(f'<line x1="{left}" y1="{y:.1f}" x2="{width - 20}" y2="{y:.1f}" stroke="#e1e5ea"/>')
        body.append(f'<text x="{left - 8}" y="{y + 4:.1f}" text-anchor="end" fill="#5a6776">%{tick}</text>')
    group_w = plot_w / len(metrics)
    names = list(result["methods"])
    bar_w = group_w * 0.8 / len(names)
    for gi, (key, label) in enumerate(metrics):
        x0 = left + gi * group_w + group_w * 0.1
        for bi, name in enumerate(names):
            entry = result["methods"][name]
            value = entry[key] or 0.0
            x = x0 + bi * bar_w
            h = plot_h * value
            body.append(f'<rect x="{x:.1f}" y="{top + plot_h - h:.1f}" width="{bar_w - 3:.1f}" height="{h:.1f}" fill="{METHOD_COLORS[name]}"/>')
            body.append(f'<text x="{x + (bar_w - 3) / 2:.1f}" y="{top + plot_h - h - 4:.1f}" text-anchor="middle" font-size="10" fill="#16202c">{value * 100:.0f}</text>')
            ci = entry.get(f"{key}_ci95")
            if ci:
                cx = x + (bar_w - 3) / 2
                body.append(f'<line x1="{cx:.1f}" y1="{top + plot_h * (1 - ci[0]):.1f}" x2="{cx:.1f}" y2="{top + plot_h * (1 - ci[1]):.1f}" stroke="#16202c" stroke-width="1.2"/>')
        body.append(f'<text x="{left + gi * group_w + group_w / 2:.1f}" y="{height - bottom + 20}" text-anchor="middle" font-weight="600">{label}</text>')
    for i, name in enumerate(names):
        lx = left + (i % 3) * 235
        ly = height - 26 + (i // 3) * 16
        body.append(f'<rect x="{lx}" y="{ly}" width="12" height="12" fill="{METHOD_COLORS[name]}"/>')
        body.append(f'<text x="{lx + 18}" y="{ly + 10}">{escape(METHOD_LABELS[name])}</text>')
    return _svg(width, height + 16, "".join(body))


def _blend(value: float) -> str:
    """Light red at 0, light green at 1."""
    low, high = (248, 215, 211), (191, 230, 207)
    red, green, blue = (round(low[i] + (high[i] - low[i]) * value) for i in range(3))
    return f"rgb({red},{green},{blue})"


def heatmap(result: dict) -> str:
    names = list(result["methods"])
    families = list(result["attack_families"])
    cell_w, cell_h, left, top = 110, 24, 300, 70
    width = left + cell_w * len(names) + 20
    height = top + cell_h * len(families) + 30
    body = [f'<text x="10" y="22" font-size="14" font-weight="600">Saldırı türüne göre duyarlılık (yakalanan / toplam)</text>']
    for ci, name in enumerate(names):
        body.append(f'<text x="{left + ci * cell_w + cell_w / 2}" y="{top - 10}" text-anchor="middle" font-size="11" font-weight="600">{escape(METHOD_LABELS[name])}</text>')
    for ri, family in enumerate(families):
        y = top + ri * cell_h
        body.append(f'<text x="{left - 10}" y="{y + 16}" text-anchor="end">{escape(ATTACK_LABELS.get(family, family))}</text>')
        for ci, name in enumerate(names):
            value = result["methods"][name]["recall_by_attack"].get(family)
            fill = "#f2f2f2" if value is None else _blend(value)
            body.append(f'<rect x="{left + ci * cell_w}" y="{y}" width="{cell_w - 2}" height="{cell_h - 2}" fill="{fill}"/>')
            text = "-" if value is None else f"%{value * 100:.0f}"
            body.append(f'<text x="{left + ci * cell_w + cell_w / 2 - 1}" y="{y + 16}" text-anchor="middle" font-weight="600">{text}</text>')
    return _svg(width, height, "".join(body))


def prevalence_chart(sweep: dict) -> str:
    width, height, left, top, bottom = 760, 360, 60, 40, 60
    plot_w, plot_h = width - left - 30, height - top - bottom
    prevalences = [float(p) for p in next(iter(sweep.values()))]
    lo, hi = math.log10(min(prevalences)), math.log10(max(prevalences))

    def x_of(p: float) -> float:
        return left + plot_w * (math.log10(p) - lo) / (hi - lo)

    body = [f'<text x="{left}" y="22" font-size="14" font-weight="600">Saldırganların oranına göre kesinlik (ölçülen duyarlılık ve yanlış alarm oranından)</text>']
    for tick in range(0, 101, 20):
        y = top + plot_h * (1 - tick / 100)
        body.append(f'<line x1="{left}" y1="{y:.1f}" x2="{width - 30}" y2="{y:.1f}" stroke="#e1e5ea"/>')
        body.append(f'<text x="{left - 8}" y="{y + 4:.1f}" text-anchor="end" fill="#5a6776">%{tick}</text>')
    for p in prevalences:
        body.append(f'<text x="{x_of(p):.1f}" y="{height - bottom + 18}" text-anchor="middle" fill="#5a6776">%{p * 100:g}</text>')
    body.append(f'<text x="{left + plot_w / 2}" y="{height - bottom + 38}" text-anchor="middle">Saldıran varlıkların oranı (logaritmik)</text>')
    for i, (name, series) in enumerate(sweep.items()):
        points = [(x_of(float(p)), top + plot_h * (1 - (v or 0))) for p, v in series.items()]
        path = " ".join(f"{x:.1f},{y:.1f}" for x, y in points)
        body.append(f'<polyline points="{path}" fill="none" stroke="{METHOD_COLORS[name]}" stroke-width="2.2"/>')
        for x, y in points:
            body.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3" fill="{METHOD_COLORS[name]}"/>')
        lx = left + (i % 3) * 235
        ly = height - 22 + (i // 3) * 16
        body.append(f'<rect x="{lx}" y="{ly}" width="12" height="12" fill="{METHOD_COLORS[name]}"/>')
        body.append(f'<text x="{lx + 18}" y="{ly + 10}">{escape(METHOD_LABELS[name])}</text>')
    return _svg(width, height + 16, "".join(body))


# -- markdown ---------------------------------------------------------------------------------
def markdown(main: dict, sweep: dict, sensitivity: list[dict], generated: str, thresholds: dict | None = None,
             stress: dict | None = None) -> str:
    m = main["methods"]
    lines: list[str] = []
    add = lines.append
    add("# SentinelAI XDR: tespit yöntemlerinin karşılaştırmalı değerlendirmesi")
    add("")
    add(f"Üretim tarihi: {generated}. Her sayı `research/` altındaki kodla yeniden üretilebilir (`python research/run_evaluation.py`).")
    add("")
    add("## 1. Araştırma sorusu")
    add("")
    add("SentinelAI XDR'daki tespit yöntemleri (şeffaf kurallar, basit eşikler, gözetimsiz makine öğrenmesi ve bunların birleşimi), "
        "etiketli bir veri üzerinde siber saldırı davranışlarını ne kadar doğru yakalıyor ve normal ama şüpheli görünen davranışlarda "
        "ne kadar yanlış alarm üretiyor?")
    add("")
    add("## 2. Yöntem")
    add("")
    add(f"- **Veri:** Tohumlu (tekrarlanabilir) bir simülatör, {main['entities_per_run']} varlıklık ağlar üretir ve her varlığa tek bir rol verir: "
        f"{len(main['benign_roles'])} iyi huylu profilden biri veya {len(main['attack_families'])} saldırı ailesinden biri. "
        "Varlık, bir kaynak IP adresi, bir Windows bilgisayarı veya bir bulut hesabıdır. Olaylar iki saatlik bir ufukta, "
        "tespit motorunun tükettiği biçimde yazılır.")
    if main.get("hard_share_of_benign") is not None:
        text = (
            f"- **Zor durumların payı (en önemli varsayım):** İyi huylu varlıkların %{main['hard_share_of_benign'] * 100:.0f}'i "
            f"saldırıya benzeyen davranış gösterir (ölçek {main['hard_scale']})"
        )
        if stress:
            text += f"; karşılaştırma için bölüm 6b'de %{stress['hard_share_of_benign'] * 100:.0f} ile de ölçüldü."
        add(text + ("" if stress else "."))
    add(f"- **Zor durumlar:** İyi huylu tarafta saldırıya benzeyen davranışlar (parolayı unutan kullanıcı, çok kullanıcılı NAT ağ geçidi, "
        "zamanlanmış güvenlik taraması, Office/WMI otomasyonu, Temp'ten çalışan kurulum, onaylı bulut değişikliği); saldırı tarafında eşiklerin altında "
        "kalmaya çalışan yavaş saldırılar.")
    add(f"- **Etiketleme birimi:** Varlık. Bir yöntem, varlığa ait olaylara dayanan bir bulgu ürettiyse o varlığı saldırgan olarak işaretlemiş sayılır.")
    add(f"- **Tekrar:** {main['seeds']} bağımsız tohum; saldırgan oranı %{main['prevalence'] * 100:g}. Isolation Forest her tohumda varlıkların %70'i üzerinde, "
        f"etiketsiz olarak eğitilir (contamination = {main['contamination']}) ve kalan %30 üzerinde değerlendirilir; diğer yöntemler eğitim gerektirmez ve aynı %30 üzerinde ölçülür.")
    add("- **Karşılaştırılan yöntemler:** (1) SentinelAI yerleşik kuralları, gerçek içe alım hattıyla aynı değerlendiriciler üzerinden; "
        f"(2) basit eşik: tüm dönemde {10}+ oturum açma hatası veya {20}+ farklı hedef port; (3) Isolation Forest (projenin altı özellikli isteğe bağlı modeli); (4) kural veya Isolation Forest.")
    add("- **Metrikler:** Kesinlik (precision), duyarlılık (recall), F1, yanlış pozitif oranı (FPR); oranlar için %95 Wilson güven aralığı. "
        "Havuzlanmış sayılar kullanılır; tohumlar arası F1 standart sapması ayrıca verilir.")
    add("")
    add("## 3. Ana sonuçlar")
    add("")
    add("| Yöntem | Kesinlik | Duyarlılık | F1 | Yanlış pozitif oranı | TP | FP | FN | TN |")
    add("|---|---|---|---|---|---:|---:|---:|---:|")
    for name, entry in m.items():
        add(f"| {METHOD_LABELS[name]} | {pct_ci(entry['precision'], entry['precision_ci95'])} | {pct_ci(entry['recall'], entry['recall_ci95'])} | "
            f"{pct(entry['f1'])} (±{pct(entry['f1_seed_sd'])[1:] if entry['f1_seed_sd'] is not None else '-'}) | "
            f"{pct_ci(entry['false_positive_rate'], entry['false_positive_rate_ci95'])} | {entry['tp']} | {entry['fp']} | {entry['fn']} | {entry['tn']} |")
    add("")
    add("![Yöntemlerin başarımı](figures/performans.svg)")
    add("")
    add("## 4. Saldırı türüne göre duyarlılık")
    add("")
    add("| Saldırı türü | " + " | ".join(METHOD_LABELS[n] for n in m) + " |")
    add("|---|" + "---|" * len(m))
    for family in main["attack_families"]:
        row = [pct(m[n]["recall_by_attack"].get(family)) for n in m]
        add(f"| {ATTACK_LABELS.get(family, family)} | " + " | ".join(row) + " |")
    add("")
    add("![Saldırı türüne göre duyarlılık](figures/duyarlilik_haritasi.svg)")
    add("")
    add("## 5. İyi huylu davranışlarda yanlış alarm oranı")
    add("")
    add("| İyi huylu rol | " + " | ".join(METHOD_LABELS[n] for n in m) + " |")
    add("|---|" + "---|" * len(m))
    for role in main["benign_roles"]:
        row = [pct(m[n]["false_positive_rate_by_benign_role"].get(role)) for n in m]
        add(f"| {ROLE_LABELS.get(role, role)} | " + " | ".join(row) + " |")
    add("")
    add("## 6. Saldırgan oranı değişirse kesinlik")
    add("")
    add("Gerçek ağlarda saldıran varlık oranı çok düşüktür ve kesinlik bu orana bağlıdır; duyarlılık ve yanlış pozitif oranı bağlı değildir. "
        "Aşağıdaki tablo, ölçülen duyarlılık ve yanlış pozitif oranından hesaplanmış **projeksiyondur** (ölçüm değildir).")
    add("")
    proportions = list(next(iter(sweep.values())))
    add("| Yöntem | " + " | ".join(f"%{float(p) * 100:g}" for p in proportions) + " |")
    add("|---|" + "---:|" * len(proportions))
    for name, series in sweep.items():
        add(f"| {METHOD_LABELS[name]} | " + " | ".join(pct(series[p]) for p in proportions) + " |")
    add("")
    add("![Saldırgan oranına göre kesinlik](figures/kesinlik_oran.svg)")
    add("")
    if stress:
        add("## 6b. Zor durumların payı değişirse")
        add("")
        add(f"Aynı simülasyon, iyi huylu varlıkların %{main['hard_share_of_benign'] * 100:.0f}'i (ana senaryo) ve %{stress['hard_share_of_benign'] * 100:.0f}'i (stres senaryosu) "
            "saldırıya benzeyen davranış gösterecek şekilde çalıştırıldı:")
        add("")
        add("| Yöntem | F1 (ana) | FPR (ana) | F1 (stres) | FPR (stres) |")
        add("|---|---:|---:|---:|---:|")
        for name in main["methods"]:
            a, b = main["methods"][name], stress["methods"][name]
            add(f"| {METHOD_LABELS[name]} | {pct(a['f1'])} | {pct(a['false_positive_rate'])} | {pct(b['f1'])} | {pct(b['false_positive_rate'])} |")
        add("")
    add("## 7. Hangi kural nerede doğru, nerede yanlış?")
    add("")
    add("Her kuralın, değerlendirme kümesinde kaç saldıran ve kaç iyi huylu varlık için bulgu ürettiği (havuzlanmış, tüm tohumlar):")
    add("")
    add("| Kural | Saldıran varlık | İyi huylu varlık (yanlış alarm) |")
    add("|---|---:|---:|")
    for rule_id, hits in sorted(main["rule_hits"].items(), key=lambda kv: -(kv[1]["false_positive_entities"] + kv[1]["true_positive_entities"])):
        add(f"| `{rule_id}` | {hits['true_positive_entities']} | {hits['false_positive_entities']} |")
    add("")
    if thresholds:
        add("## 8. Eşik duyarlılık analizi (kural başına)")
        add("")
        add("Her kuralın tek bir eşiği değiştirildi; duyarlılık yalnızca kuralın hedeflediği saldırı ailelerinde, yanlış pozitif oranı tüm iyi huylu varlıklarda ölçüldü. "
            "Varsayılan eşik **kalın** gösterilir. Eşiği bu veriye göre \"en iyi\" seçmek döngüsel olurdu; tablo yalnızca ödünleşimi gösterir.")
        add("")
        for rule_id, info in thresholds.items():
            add(f"**`{rule_id}`** (`{info['parameter']}`; hedef: {', '.join(ATTACK_LABELS.get(t, t) for t in info['targets'])})")
            add("")
            add("| Eşik | Duyarlılık | Yanlış pozitif oranı |")
            add("|---:|---:|---:|")
            for point in info["points"]:
                value = f"**{point['value']}**" if point["default"] else str(point["value"])
                add(f"| {value} | {pct(point['recall'])} | {pct_ci(point['false_positive_rate'], point['false_positive_rate_ci95'])} |")
            add("")
        add("![Eşik taraması](figures/esik_taramasi.svg)")
        add("")
    add("## 9. Isolation Forest duyarlılık analizi")
    add("")
    add("| contamination | Kesinlik | Duyarlılık | F1 | FPR |")
    add("|---|---|---|---|---|")
    for entry in sensitivity:
        f = entry["methods"]["forest"]
        add(f"| {entry['contamination']} | {pct(f['precision'])} | {pct(f['recall'])} | {pct(f['f1'])} | {pct(f['false_positive_rate'])} |")
    add("")
    add("## 10. Sınırlılıklar (okumadan önce)")
    add("")
    add("- **Veri sentetiktir.** İyi huylu ve kötü amaçlı davranışın nasıl göründüğü varsayımı simülatörü yazanlara aittir ve kurallar da aynı kişilerce yazılmıştır; "
        "bu, kurallar lehine bir yanlılık yaratır. Sonuçlar \"bu varsayımlar altında davranış\"ı ölçer, gerçek bir ağdaki yanlış alarm oranını değil.")
    add("- **Etiket birimi varlıktır, olay değil.** Bir saldırganın tek bir olayını yakalamak varlığı yakalanmış sayar; saldırının ne kadarının görüldüğü ölçülmez.")
    add("- **Parametreler ayarlanmadı.** Kural eşikleri ve Isolation Forest ayarları ne bu veriye göre seçildi ne de optimize edildi; bu nedenle sonuçlar bir üst sınır değildir.")
    add("- **Bulut ve uç nokta olayları** Isolation Forest ve basit eşik için görünmezdir (bu özellikler yalnızca oturum açma ve ağ sayımlarını kullanır). Bu, yöntemlerin eşit koşulda karşılaştırıldığı anlamına gelmez; "
        "kurallar daha fazla veri türünü görür.")
    add("- **Etiketli gerçek veri yok.** İyi huylu ve saldırı etiketli bir gerçek veri kümesiyle ölçüm yapılmadı; kod `--dataset` ile bunu alacak biçimde hazırdır. "
        "Yalnızca saldırı içeren sekiz halka açık Windows kaydında kuralların duyarlılığı ayrıca denendi (GERCEK_VERI.md); orada yanlış alarm ölçülemez.")
    add("- **Tek koşullu dönem:** İki saatlik ufuk ve sabit pencere hizalaması; pencere sınırını aşan yavaş saldırılar bu nedenle daha da zor yakalanır.")
    return "\n".join(lines) + "\n"


def sweep_chart(thresholds: dict) -> str:
    width, height, left, top, bottom = 760, 420, 60, 40, 70
    plot_w, plot_h = width - left - 30, height - top - bottom
    palette = ["#1f5fbf", "#c47a00", "#1b7a46", "#b3261e", "#6f42c1", "#00838f"]
    max_fpr = max((p["false_positive_rate"] or 0) for info in thresholds.values() for p in info["points"]) or 1.0
    max_fpr = min(1.0, max(0.1, math.ceil(max_fpr * 10) / 10))
    body = [f'<text x="{left}" y="22" font-size="14" font-weight="600">Eşik taraması: duyarlılık ve yanlış pozitif oranı (her nokta bir eşik değeri; dolu nokta varsayılan)</text>']
    for tick in range(0, 101, 20):
        y = top + plot_h * (1 - tick / 100)
        body.append(f'<line x1="{left}" y1="{y:.1f}" x2="{width - 30}" y2="{y:.1f}" stroke="#e1e5ea"/>')
        body.append(f'<text x="{left - 8}" y="{y + 4:.1f}" text-anchor="end" fill="#5a6776">%{tick}</text>')
    for i in range(0, 6):
        value = max_fpr * i / 5
        x = left + plot_w * i / 5
        body.append(f'<text x="{x:.1f}" y="{height - bottom + 18}" text-anchor="middle" fill="#5a6776">%{value * 100:.0f}</text>')
    body.append(f'<text x="{left + plot_w / 2}" y="{height - bottom + 38}" text-anchor="middle">Yanlış pozitif oranı (iyi huylu varlıklarda)</text>')
    for index, (rule_id, info) in enumerate(thresholds.items()):
        color = palette[index % len(palette)]
        pts = [(left + plot_w * ((p["false_positive_rate"] or 0) / max_fpr), top + plot_h * (1 - (p["recall"] or 0)), p) for p in info["points"]]
        body.append(f'<polyline points="{" ".join(f"{x:.1f},{y:.1f}" for x, y, _ in pts)}" fill="none" stroke="{color}" stroke-width="1.8"/>')
        for x, y, p in pts:
            fill = color if p["default"] else "#ffffff"
            body.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="4" fill="{fill}" stroke="{color}" stroke-width="1.6"/>')
        lx = left + (index % 3) * 235
        ly = height - 24 + (index // 3) * 16
        body.append(f'<rect x="{lx}" y="{ly - 10}" width="12" height="12" fill="{color}"/>')
        body.append(f'<text x="{lx + 18}" y="{ly}">{escape(rule_id)}</text>')
    return _svg(width, height + 16, "".join(body))
