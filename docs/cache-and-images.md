# Cache a úspory obrázků na Ubuntu

HomeProxy 1.2.5 navazuje na opravu komprese při vypnuté cache a Ubuntu ikon
z 1.2.4 a přidává rozsah kontroly všech podporovaných HTTPS webů.
Cache a komprese se ovládají nezávisle.
Aktualizujte server i desktop společně; uložené nastavení ani důvěra klientů
se tím automaticky nemění.

## Jak vzniká úspora

Zapněte Veřejnou cache v Nastavení a změnu uložte. První požadavek na
způsobilý veřejný soubor stáhne obsah z originu a uloží jej; další požadavek
může využít HIT a připsat skutečně předané bajty do úspory cache. Soubor musí
respektovat veřejnou politiku, čerstvost a nastavené limity. Cookies, přihlášení,
private/no-store a soukromý obsah se nesdílejí. Od 1.2.8 stačí odpověď s výslovnou
dobou platnosti (`max-age` nebo `s-maxage`, nejen `public`) a obrázky, fonty, audio
a video načtené prohlížečem se ukládají i s dotazem v adrese (celá adresa je součástí
klíče). Skripty a styly s dotazem se dál neukládají, protože takové adresy často
vracejí obsah přizpůsobený prohlížeči. Prohlížeč se signálem `Sec-GPC`/`DNT` má vlastní
kopie a signál se předává webu. Veřejné HTML a ostatní adresy s dotazem vyžadují výslovně povolený veřejný
endpoint. Požadavky s hlavičkou `Origin` (fonty, CORS) mají vlastní kopii pro každý
web. Způsobilé částečné odpovědi lze ukládat také.

Komprese Vyvážená a další zapnuté profily zpracují podporované JPEG a jednoduché
PNG i bez cache. Úprava musí ušetřit nejméně 8 KiB a 10 %; malé nebo již
optimalizované obrázky, WebP/AVIF, nepodporovaná metadata a nebezpečné vstupy
se přenesou jako originál. Nulový dočasný buffer kompresi vypíná; streamovanou
diskovou cache ponechává. Klientský i serverový pokyn no-transform se respektuje.

Běžný HTTPS a SOCKS tunel přenáší šifrovaná data bez cache a komprese. Pro
podporovaný HTTPS web zvolte Kontrolu HTTPS webů, připravte veřejnou CA,
na každém klientovi skutečně nastavte důvěru a zvolte rozsah Všechny podporované
weby nebo Vybrané domény s konkrétním seznamem.
Stažení CA ani QR důvěru nepotvrzuje. Kontrola může číst i soukromé stránky;
optimalizují se jen způsobilé veřejné odpovědi. Výjimky, nevybrané domény a některé
nekompatibilní aplikace zůstávají tunelem. Podrobnosti jsou v
[HTTPS a offline obsahu](https-offline.md) a [připojení klienta](device-certificate-setup.md).

## Proč se HTTPS necachuje

Cache vidí jen obsah, který proxy skutečně dešifruje. HTTPS se ukládá pouze tehdy,
když je v uloženém nastavení služby zapnutá Kontrola HTTPS webů s potvrzenou
důvěrou klientů a neprázdným rozsahem a když prohlížeč nebo aplikace certifikátu
HomeProxy CA skutečně důvěřuje. Jinak Domov u cache ukazuje „Veřejná · 8 GiB ·
jen HTTP“.

- **Tunel**: SOCKS5, režim Tunel, nevybrané domény, vlastní výjimky a vestavěné
  výjimky pro video a Google/YouTube přenáší šifrovaná data beze změny.
- **Odmítnutá CA**: když klient po obdržení certifikátu HomeProxy handshake odmítne
  nebo nedokončí, proxy si pro danou IP a doménu zapamatuje tunelovou výjimku na
  6 hodin. Spojení, které prohlížeč otevře do zásoby a zavře ještě před TLS
  (preconnect), se od 1.2.8 jako odmítnutí nepočítá.
- **Soukromý obsah**: požadavky s cookies nebo přihlášením, navigace a dotazy mimo
  obrázky, fonty a média prohlížeče (bez povoleného veřejného endpointu) a odpovědi
  `private`, `no-store`, `Set-Cookie` či bez výslovné doby platnosti se mezi
  zařízeními nesdílejí.

Důvody vidíte na Domově v části Účinek optimalizací (tři nejčastější důvody vynechání
cache od spuštění služby) a u jednotlivých záznamů Aktivity. Na serveru je vypíše
`homeproxy --json status` v `stats.cacheBypassReasons` a souhrnně
`scripts/homeproxy-healthcheck.py`, který také varuje, když je zapnutá cache
s kontrolou HTTPS, ale po 50 vynecháních nemá ani jeden HIT.

## Co znamená 0 B

Na Domově se zobrazují skutečné úspory cache a komprese od spuštění služby.
Restart daemonu čítače vynuluje, i když disková cache přetrvá. Blokované reklamy
se do bajtů neodhadují. Vysvětlení vedle čítače vychází z uloženého nastavení
služby; neuložený návrh v Nastavení je neovlivní. Samotných 0 B neprokazuje
poruchu cache: obsah mohl projít tunelem, nesplňovat podmínky nebo ještě
nebyl použit opakovaně.

Pro reprodukci použijte veřejný podporovaný obrázek přes skutečnou proxy a
porovnejte první a opakovaný požadavek. Při nejasnosti exportujte diagnostiku
z Domova; nezapínejte automaticky HTTPS kontrolu ani nesnižujte ochrany cache.

## Vynulování přenosu

Od verze 1.2.6 je v horním přehledu přenosu ikona kruhové šipky. Po potvrzení
začne počítat odeslaná a přijatá data od nuly, včetně pokračujících spojení.
Proxy běží dál; rychlosti, úspory, historie a kvóty se zachovají.
Zavření okna ani vypnutí a zapnutí proxy toto období nezmění. Restart služby
začne nové období od spuštění, stejně jako dříve.

In version 1.2.6, the circular-arrow button in the traffic summary resets sent
and received totals after confirmation. Transfers continue; rates, savings,
history and quotas are preserved. Reopening the window or stopping and starting
the proxy keeps the current period. Restarting the service starts a new period.
