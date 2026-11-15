# Microsoft Entra ile SSO, grup eşleme ve SCIM kurulumu

**Durum:** Bu adımlar kodu ve Microsoft'un belgelenmiş davranışını izler; **gerçek bir Entra kiracısıyla
uçtan uca denenmedi** (SSO girişi bu projede Entra ile denendi, SCIM ve `groups` claim'i denenmedi). İlk
kurulumda her adımı doğrulayın ve sorun çıkarsa `docs/STATUS.md` notlarına göre hatayı bildirin.

## 1. SSO (zaten çalışıyor)

`OIDC_*` ayarları `DEPLOYMENT.md` içinde. Uygulama kaydında yönlendirme adresi ürünün HTTPS adresidir
(`https://<alan>/api/v1/auth/oidc/callback`). SSO yalnızca **önceden var olan** hesaplarla çalışır; hesap
oluşturmak için 3. veya 4. bölümü kullanın.

## 2. Grupları jetona koymak

Entra'da uygulama kaydı → **Token configuration** → **Add groups claim** → Security groups → ID token
için **Group ID**. Uygulama bu değeri (grubun **Nesne Kimliği**) `groups` alanından okur.

Bilinen sınır: bir kişi çok sayıda gruba üyeyse (yaklaşık 200 üstü) Entra jetona liste koymaz, bir
"fazlalık" bağlantısı koyar. Uygulama bunu **izlemez**; bu kişilerde eşleme boş kalır ve mevcut rolleri
korunur. Çözüm: Entra'da "Groups assigned to the application" seçeneğiyle yalnızca uygulamaya atanmış
grupları göndermek.

Alternatif olarak **App roles** tanımlayıp rol değerlerini (`roles` alanı) eşleyebilirsiniz.

## 3. Grup → rol eşlemesi (ürün tarafı)

**Kullanıcılar** sayfası → "Şirket girişi (SSO) ve roller":

1. Grup Nesne Kimliğini yazın, bir rol seçin, **Eşleme ekle**.
2. **Rolleri gruplarla eşit tut:** her girişte roller eşlenen rollere ayarlanır. Eşlenmiş grubu olmayan kişi
   rollerini korur; son yönetici asla düşürülmez.
3. **İlk girişte hesap oluştur:** açılırsa, hesabı olmayan ama eşlenmiş bir grubu olan kişiye hesap açılır.
   Eşlenmiş grubu yoksa (ve varsayılan rol seçilmediyse) giriş reddedilir. Varsayılan rol **yönetici
   olamaz**.

## 4. SCIM ile hesap yaşam döngüsü

1. Aynı sayfada **Otomatik hesap yönetimi (SCIM)** → ad verip **Jeton oluştur**. Jeton **bir kez**
   gösterilir; kopyalayın.
2. Entra'da **Enterprise applications** → uygulama → **Provisioning** → Automatic:
   - **Tenant URL:** `https://<alan>/api/v1/scim/v2`
   - **Secret Token:** kopyaladığınız jeton
   - **Test Connection**. (`/scim/v2/Users` yanıt vermeli.)
3. **Mappings** → Users: `userPrincipalName` → `userName`, `displayName` → `displayName`,
   `Switch([IsSoftDeleted], , "False", "True", "True", "False")` → `active`. İsteğe bağlı: bir uygulama rolü
   alanını `roles[value]` ile eşleyin (yalnızca `analyst`, `auditor`, `ingestion_service` değerleri
   kabul edilir).
4. Kişi uygulamaya atanınca hesap açılır (parola yok; yalnızca SSO ile girer). Atama kaldırılınca veya
   kişi devre dışı kalınca hesap **kapatılır** ve oturumları anında biter. Hesaplar silinmez (denetim
   kayıtları bozulmasın diye).

Önemli kurallar:

- SCIM **yönetici rolü veremez**. Yöneticiler elle veya açık bir grup eşlemesiyle belirlenir.
- SCIM, son aktif yöneticiyi kapatamaz veya düşüremez (409).
- Hata gövdeleri SCIM şemasında değil, uygulamanın kendi biçimindedir; Entra yalnızca durum kodlarına bakar.
- Gruplar (`/Groups`) senkronize edilmez; roller `roles` alanından veya SSO grup eşlemesinden gelir.

## 5. Sınama listesi (ilk kurulumda sırayla)

- [ ] Test kullanıcısı SSO ile giriyor ve beklenen rolü alıyor.
- [ ] Grup eşlemesi: kişiyi gruba ekle/çıkar, bir sonraki girişte rol değişiyor.
- [ ] SCIM Test Connection başarılı; atanan kişi hesap olarak görünüyor.
- [ ] Atamayı kaldır: hesap kapalı, açık oturum anında sonlandı.
- [ ] Denetim sayfasında `scim.user_created`, `scim.user_updated`, `auth.sso_roles_synced` kayıtları var.
