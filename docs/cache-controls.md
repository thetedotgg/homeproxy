# Cache: limity a skutečný rozsah

Platí pro HomeProxy 1.1.4 a novější / Ubuntu preview; rozšíření bylo ověřeno nad základem 1.1.3 (`6a27eb0370c154a421ad64292b438082d96867d7`). CLI a desktop řídí jeden daemon a jednu diskovou cache. HTTPS Inspect daemon odmítá; žádné certifikáty ani nastavení klientských aplikací se nemění.

## Nastavení a jednotky

Desktop: **Nastavení → Veřejná cache**. Hodnoty lze připravit i při vypnuté cache. Ukládají se akcí Uložit; přehled odlišuje uložené limity od návrhu.

| JSON / CLI pole | Celý rozsah | Výchozí | Význam |
| --- | --- | --- | --- |
| `cacheLimitGib` | 1–1024 GiB | 8 GiB | Logické délky diskových těl, metadat a dočasných souborů. Místo na SSD se předem nealokuje. |
| `cacheMaxObjectMib` | 1–1024 MiB | 1024 MiB | Největší tělo ukládaného objektu, také omezení HIT starších položek. Nad limit běžný přenos bez uložení. |
| `responseBufferLimitMib` | 0–8 MiB | 8 MiB | Největší HTTP tělo sbírané do dočasného RAM bufferu; větší se streamuje. |
| `responseBufferBudgetMib` | 0–512 MiB | 64 MiB | Společný rozpočet těchto těl a rezervovaných výstupů obrazových transformací; při vyčerpání streamování / původní obrázek. |

1 MiB = 1 048 576 B; 1 GiB = 1 073 741 824 B = 1024 MiB. Limit bufferu musí být nejvýše společný rozpočet. Nulový rozpočet vyžaduje nulový buffer. Nula vypne sbírání celých těl a transformaci obrázků, zachová přenos i streamovanou diskovou cache. Cache zůstává standardně vypnutá. Staré profily získají výchozí hodnoty nových polí; původní 2/8/20 GiB zůstávají platné.

```sh
homeproxy config apply --stdin <<'JSON'
{"cacheEnabled":true,"cacheLimitGib":20,"cacheMaxObjectMib":1024,"responseBufferLimitMib":8,"responseBufferBudgetMib":64}
JSON
homeproxy config check
homeproxy cache status
homeproxy --json cache status
```

Změna limitů restartuje proxy posluchače jako ostatní nastavení a může přerušit aktivní přenosy. Samotný přepínač cache zůstává okamžitý bez restartu tunelů. Neplatné hodnoty daemon odmítne atomicky (`invalid_config`, CLI exit 5); chybný místní JSON je chyba vstupu (exit 2). Nastavení přežije restart. Starší desktop s neúplným objektem nastavení potřebuje odpovídající verzi; daemon jeho zápis odmítne místo ztráty nových hodnot.

Kapacita se vynucuje při spuštění, změně i dalších přístupech. Po snížení se položky odstraní; při aktivním čtení/zápisu může údržba počkat na uvolnění a další přístup. Cache má také maximum 8192 položek a limity hlaviček. Rezerva metadat může zabránit uložení těla těsně u kapacity disku. Vypnutí cache soubory samo nesmaže; slouží k tomu `homeproxy cache clear`. Selhání zápisu zachová přenos původního těla.

Přehled počítá logické délky souborů, nikoli fyzické bloky, volné místo SSD či RAM. Nezměněný adresář se přeměřuje nejvýše jednou za 5 sekund, po změně může následovat dřívější přeměření. Scan nedrží zámek přes celý průchod; při souběžném zápisu je výsledek označen jako starší/přibližný (`usageIsCurrent=false`). `measured=false` znamená, že dosud neproběhlo úspěšné měření. `measurementError` a `maintenanceError` odlišují selhání měření a údržby. Neznámý údaj se nezobrazuje jako nula. Trvale selhávající údržba má odstup 5 sekund mezi pokusy; bezpečné HIT mohou pokračovat při čekajícím prořezání, po požadavku na vymazání zůstávají zneplatněné.

## Disk, RAM a příklad Squidu

HomeProxy nemá samostatnou dlouhodobou RAM cache. HIT ověřuje délku, celý SHA-256 a čerstvost diskového souboru a streamuje jej po 64 KiB. Velké způsobilé odpovědi se zapisují po částech; celý 1GiB objekt není v RAM. Úplné tělo a EOF jsou nutné před zveřejněním položky. Přerušený přenos/trailers se neuloží.

Rozpočet bufferů **není limit paměti procesu**: nezahrnuje síťové/HTTP/TLS buffery, cache I/O, metadata, runtime, dekodér ani OS page cache. Dekodér má zvlášť limit 64 MiB, 12 milionů pixelů a jeden souběžný transform; nejde o úplný RSS limit. Omezování celé služby by vyžadovalo samostatné měření a správu prostředků procesu.

| Squid příklad | HomeProxy alternativa |
| --- | --- |
| `cache_dir … 20480 …` | `cacheLimitGib:20`, bez kopírování UFS struktury. |
| `maximum_object_size 1024 MB` | `cacheMaxObjectMib:1024`, zachované bezpečné maximum 1 GiB. |
| `cache_mem 512 MB` | RAM cache není; dočasný bufferový rozpočet lze zvýšit na 512 MiB, ale má jiný účel. Výchozích 64 MiB zachováno. |
| `maximum_object_size_in_memory 32 MB` | RAM objekty nejsou; dočasný buffer lze omezit/vypnout, jeho maximum zůstává 8 MiB. Větší těla používají diskový stream. |

## Co se cachuje

Ověřeno z `crates/homeproxy-core/src/proxy.rs` (`request_is_shared_cache_eligible`, `response_cache_ttl`, `forward_web_request`), `cache.rs` a `cache/stream.rs`:

| Cesta | Chování Ubuntu HomeProxy |
| --- | --- |
| Plain HTTP přes HTTP proxy | Jen způsobilý GET/200, explicitní `public` nebo `s-maxage`, kladná čerstvost, známá délka a tělo pod limity. |
| Soukromé/přihlášené HTTP | Cookie, Authorization, query nebo nepovolené request headers se vynechají. Žádné Set-Cookie, private, no-store, no-cache či attachment odpovědi. Soukromý obsah se vůbec neukládá, ani per-device. |
| HTML/navigace | Accept HTML a navigační Sec-Fetch znamenají bypass; nelze slibovat cache všech stránek. |
| HTTP Range / 206 | Bez cache; dílčí rozsahy se neskládají. |
| HTTPS / HTTP CONNECT | Tunel bez cache a komprese obsahu. CONNECT může přenášet i jiný TCP protokol. |
| SOCKS5 TCP | Relay bajtů bez HTTP cache, i při plain HTTP uvnitř. SOCKS sám není šifrování; zde se jeho obsah neparsuje. |
| SOCKS5 UDP / QUIC | Bez cache; aplikace může QUIC používat i mimo explicitní proxy. |
| WebSocket / provoz mimo proxy | Bez HTTP cache. Aplikace ignorující proxy HomeProxy vůbec neovlivní. |

Čerstvost nejvýše 24 hodin, případně méně podle originu a stáří. Další den tedy nemusí být HIT ani způsobilé HTTP. Klíč zahrnuje URL, Accept/jazyk a profil komprese; kapacita/počet položek mohou vyvolat dřívější vyřazení. Politika je přísnější podmnožinou standardu. [RFC 9111, ukládání](https://www.rfc-editor.org/rfc/rfc9111.html#section-3).

## SmartTube, Google Play a aktualizace

**Ověřeno:** Ubuntu odmítá Inspect; CONNECT a SOCKS přeposílají bajty. YouTube/googlevideo/ytimg mají navíc end-to-end bypass i v zachované historické inspection větvi. Tunel obecně není HTTP cache. [RFC 9110, CONNECT](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6).

Oficiální SmartTube, ověřený commit `a7212c531ac06ec87108180d5d8ab1bebebe528e`, vybírá DASH, SABR, DASH live, HLS live nebo přímé URL. ExoPlayer datové zdroje zahrnují OkHttp/Cronet/výchozí HTTP; přibalený HTTP zdroj umí HTTPS a Range. To dokazuje možnosti, nikoli skutečnou cestu Janiina přenosu. [Controller](https://github.com/yuliskov/SmartTube/blob/a7212c531ac06ec87108180d5d8ab1bebebe528e/common/src/main/java/com/liskovsoft/smartyoutubetv2/common/app/models/playback/controllers/VideoLoaderController.java#L306-L325), [datové zdroje](https://github.com/yuliskov/SmartTube/blob/a7212c531ac06ec87108180d5d8ab1bebebe528e/common/src/main/java/com/liskovsoft/smartyoutubetv2/common/exoplayer/ExoMediaSourceFactory.java#L125-L189), [Range](https://github.com/yuliskov/SmartTube/blob/a7212c531ac06ec87108180d5d8ab1bebebe528e/exoplayer-amzn-2.10.6/library/core/src/main/java/com/google/android/exoplayer2/upstream/DefaultHttpDataSource.java#L549-L554).

Google uvádí Android Enterprise stahování aplikací/aktualizací a Play API na TCP/443. Play generuje APK podle konfigurace zařízení; stejné jméno aplikace nezaručuje stejný soubor. Nejde o měření domácího telefonu ani důkaz, že každý historický/OEM download vždy používá HTTPS. [Síťové požadavky](https://support.google.com/work/android/answer/10513641), [App Bundles](https://developer.android.com/guide/app-bundle).

**Závěr:** Přenos přes HTTPS/CONNECT nebo SOCKS se neuloží. Větší disk/buffer to nezmění. Ani plain HTTP s Range, query tokenem nebo attachment nesplní dnešní politiku. Obecná aktualizace splňující veřejné HTTP podmínky se uložit může, v rámci velikosti a čerstvosti; univerzální cache aktualizací neslibujeme.

**Vyžaduje měření:** Zda konkrétní TV/Play používají HomeProxy, protokol médií, změny kvality/URL a objem opakovaných bajtů. S oprávněním vlastníka porovnat stejný obsah dvakrát, protokol/host a přenosy, HIT/MISS/bypass. Nedávat tokeny/plné soukromé URL do sdílených reportů. Domácí zařízení se v tomto úkolu neměřila. Tvrzení „skoro vše už teče přes SOCKS“ není dosavadním kódem ani tímto vývojem doložené.

## Shrnutí pro uživatele

HomeProxy nyní umí nastavit kapacitu diskové cache, největší objekt a dočasné HTTP buffery. Ukládá jen bezpečně způsobilé veřejné nešifrované HTTP odpovědi; výchozí maximum objektu je 1 GiB. HTTPS a SOCKS pouze přenáší, takže opakované video SmartTube nebo download Google Play přes tyto cesty znovu spotřebuje data. Větší cache to nevyřeší. Konkrétní TV/telefon je potřeba změřit; zatím nevíme, zda a kudy skutečně používá proxy. Buffer není dlouhodobá RAM cache ani limit celé aplikace.
