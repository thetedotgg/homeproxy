# HomeProxy

**Klidná domácí proxy pro celou domácnost.** HomeProxy běží na jednom počítači doma a telefony, notebooky i televize ze stejné sítě přes něj chodí na internet. Blokuje reklamy, ukládá vhodný veřejný obsah a umí zmenšit obrázky, takže domácnost spotřebuje méně dat. Vidíte, co které zařízení dělá, a můžete ho omezit nebo zablokovat.

HomeProxy je zdarma a s otevřeným zdrojovým kódem. [English](README.md) · [Web](https://homeproxy.thetasigma.io)

## Stažení

| Systém | Ke stažení |
|---|---|
| Windows 10/11 (x64) | [HomeProxy-Setup-x64.exe](https://github.com/thetedotgg/homeproxy/releases/latest/download/HomeProxy-Setup-x64.exe) |
| Ubuntu 22.04 a novější (amd64) | [HomeProxy-Ubuntu-amd64.tar.gz](https://github.com/thetedotgg/homeproxy/releases/latest/download/HomeProxy-Ubuntu-amd64.tar.gz) |

Všechny soubory a kontrolní součty SHA-256 najdete u [posledního vydání](https://github.com/thetedotgg/homeproxy/releases/latest).

**Windows:** spusťte instalátor. Zatím není digitálně podepsaný, takže SmartScreen může ukázat *Systém Windows ochránil váš počítač*. Pokud jste soubor stáhli z odkazu výše, zvolte **Další informace → Přesto spustit**.

**Ubuntu:** rozbalte archiv, v terminálu spusťte instalátor a pak se odhlaste a znovu přihlaste:

```sh
tar -xzf HomeProxy-Ubuntu-amd64.tar.gz
cd HomeProxy-Ubuntu-amd64
./install.sh
```

Instalátor ověří kontrolní součty a nainstaluje dva balíčky: systémovou službu `homeproxy` a aplikaci `homeproxy-desktop`. Služba běží dál i po zavření okna.

## Připojení zařízení

Otevřete HomeProxy, zapněte proxy pro domácí síť a projděte průvodce **Jak začít**. Ukáže adresu, port, jméno a přístupový klíč, které zadáte v nastavení proxy (na telefonu a televizi u Wi-Fi), a QR kód pro instalaci certifikátu HomeProxy, pokud zapnete kontrolu HTTPS. Přihlášení je ve výchozím stavu povinné a kterékoli zařízení můžete v aplikaci zablokovat.

Počítač s HomeProxy musí zůstat zapnutý a nesmí usnout. Na videu se neušetří a stránky, kde jste přihlášení (třeba internetové bankovnictví), cookies ani jiný soukromý obsah se nikdy neukládají.

## Co umí

- **Blokování reklam** ve třech úrovních: Vypnuto, Mírné, Přísné.
- **Veřejná cache** pro obsah, který je bezpečné sdílet (2, 8 nebo 20 GB); soukromé, přihlášené a `no-store` odpovědi se neukládají.
- **Zmenšování obrázků** pro úsporu mobilních nebo měřených dat.
- **Přehled provozu** s dnešní úsporou a aktivitou jednotlivých zařízení.
- **Pravidla pro zařízení**: zablokování, datové limity a časová pravidla.
- **Volitelná kontrola HTTPS** jen pro weby, které vyberete. Je vypnutá, dokud nepřipravíte certifikát HomeProxy a nedůvěřujete mu na každém zařízení; chatovací aplikace, hovory a YouTube jdou vždy šifrovaným tunelem a další weby, třeba banku, přidáte mezi výjimky.
- **Příprava offline** vybraných veřejných stránek a souborů.
- **Diagnostika a automatická obnova** bez terminálu.

Nic se nikam neodesílá: HomeProxy nemá telemetrii, účet ani cloudovou službu.

## Dokumentace

- [Služba a příkazová řádka na Ubuntu](docs/ubuntu-server.md) (anglicky)
- [Připojení zařízení pomocí QR](docs/device-certificate-setup.md)
- [HTTPS cache a offline režim](docs/https-offline.md)
- [Cache a úspory obrázků](docs/cache-and-images.md)
- [Limity cache a rozsah protokolů](docs/cache-controls.md)
- [Dlouhodobý provoz a obnova spojení](docs/connection-resilience.md)
- [Diagnostika a automatická obnova](docs/diagnostics-and-recovery.md)
- [Vydávání verzí](docs/releasing.md) (anglicky)

## Sestavení ze zdrojů

Postup je v [anglickém README](README.md#build-from-source) a v [CONTRIBUTING.md](CONTRIBUTING.md).

## Podpora projektu

HomeProxy je zdarma. Pokud vám šetří data nebo nervy, můžete jeho vývoj podpořit: viz [web](https://homeproxy.thetasigma.io/cs/#podpora).

## Bezpečnost a licence

Zranitelnosti prosím hlaste neveřejně podle [SECURITY.md](SECURITY.md). HomeProxy je licencován pod [GNU General Public License v3.0 nebo novější](LICENSE).
