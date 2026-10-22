# HTTPS cache a offline režim

HomeProxy 1.2.5 přidává volitelnou kontrolu všech podporovaných HTTPS webů; 1.2.7 ji upravuje pro stabilní YouTube na Android zařízeních a 1.2.8 opravuje cachování v současných prohlížečích. Aktualizujte server i desktop společně. Aktualizace neinstaluje certifikáty do klientů, nenastavuje router a neaktivuje kontrolu automaticky; původní seznam domén se zachová.

## Zapnutí HTTPS cache

1. V nastavení připravte CA a stáhněte veřejný certifikát. Alternativně použijte `homeproxy tls prepare` a `homeproxy tls export --format pem --output HomeProxy-CA.pem`.
2. Porovnejte SHA-256 otisk a nastavte důvěru v certifikát na vlastních kompatibilních klientech. Soukromý klíč neopouští daemon. Android aplikace nemusí uživatelskou CA přijmout.
3. V rozsahu kontroly zvolte „Všechny podporované weby“, chcete-li kontrolovat kompatibilní weby bez seznamu. Nebo ponechte „Vybrané domény“ a vyplňte přesné domény, případně `*.example.org` pro subdomény. Wildcard nezahrnuje základní doménu. Výjimky a vestavěné výjimky pro chat/pinned/video služby mají přednost v obou rozsazích.
4. Potvrďte připravení klientů, zvolte kontrolu HTTPS a zapněte veřejnou cache. Uložení restartuje aktivní spojení. Samotná příprava CA inspection nezapíná.
5. Pro veřejné HTML nebo adresy s query přidejte konkrétní veřejný endpoint `doména/cesta`. Volba nezpřístupní obsah s cookies, autorizací ani odpovědi `private`/`no-store`/`Set-Cookie`. Celá URL včetně query a bezpečné varianty hlaviček zůstávají součástí cache klíče.

Požadavek musí projít přes HomeProxy. HTTP proxy s CONNECT může používat inspection; obsah surových SOCKS5 tunelů se neukládá. Nevyřeší se tím QUIC, VPN ani aplikace, které proxy ignorují. HTTPS kontrola ověřuje certifikát originu; chyba TLS se neobchází starou cache.

Kontrola umožňuje HomeProxy číst i přihlášené stránky a soukromý obsah na hostech zahrnutých do rozsahu. Jen způsobilé veřejné odpovědi lze uložit a komprimovat. `no-transform`, cookies, autorizace, `private`, `no-store` a další ochrany zůstávají účinné. „Všechny podporované weby“ nepovoluje automaticky veřejné HTML ani adresy s query; od 1.2.8 je výjimkou query u obrázků, fontů, audia a videa, které prohlížeč označí hlavičkou `Sec-Fetch-Dest`, a odpověď s `max-age` bez `public` (požadavek bez cookies a přihlášení).

Po odmítnutí certifikátu nebo nedokončeném klientském TLS handshaku (timeout) si proxy pro danou IP klienta a doménu na 6 hodin zapamatuje tunelovou výjimku (do verze 1.2.6 jen 10 minut po odmítnutí, takže aplikace selhávala opakovaně). Od verze 1.2.8 se počítá jen klient, který skutečně komunikoval: odmítl nebo nedokončil handshake po certifikátu HomeProxy, nebo poslal data, která nejsou TLS (například obfuskovaný protokol na portu 443). Spojení zavřené nebo nečinné ještě před prvními daty (běžný preconnect prohlížečů) výjimku nevytvoří, takže kontrola a cache zůstanou zapnuté. Protokol, kde první mluví server (například SSH přes port 443), proto potřebuje doménu v seznamu bez kontroly. Až další CONNECT pak přenáší původní TLS; aplikace musí spojení znovu otevřít. První selhání nelze opravit ve stejném spojení a odmítnutí po dokončeném handshaku se nemusí rozpoznat. Pro trvalou výjimku použijte seznam domén bez kontroly. Neobcházejte varování certifikátu. YouTube/SmartTube a další vestavěné video výjimky dál používají tunel; libovolná aplikace ani Google Play nemají zaručenou optimalizaci.

Od verze 1.2.7 rozsah „Všechny podporované weby“ navíc nekontroluje doprovodné Google/YouTube hosty, které aplikace na Android TV a telefonech používají vedle videa: `google.com`, `googleapis.com`, `gstatic.com`, `ggpht.com`, `googleusercontent.com`, `youtu.be`, `youtube-nocookie.com` a `youtubekids.com` včetně subdomén. Jde o přihlášení, ověření aplikace, API a náhledy kanálů; při kontrole je aplikace s uživatelskou CA odmítaly a YouTube vypadával. Domény z této skupiny lze kontrolovat jen v rozsahu „Vybrané domény“, kde je výslovně uvedete; skrytý seznam v plném rozsahu je znovu nezapne. Patří sem i `gvt1.com`–`gvt3.com` a `android.com` (aktualizace a soubory Play/YouTube, kontrola připojení) a reklamní `doubleclick.net`, `googleadservices.com`, `googlesyndication.com`, pokud je nefiltruje blokování reklam, a telemetrie `google-analytics.com`, `googletagmanager.com`, `app-measurement.com`, `crashlytics.com`.

Generované certifikáty kontrolovaných webů platí 30 dní; od verze 1.2.7 je dlouho běžící daemon vydá znovu 7 dní před koncem platnosti, takže kontrola nepřestane fungovat po měsíci nepřetržitého běhu.

Verze 1.2.8 opravuje chyby, kvůli kterým se HTTPS (i HTTP) v současném Chrome a Firefoxu necachovalo: požadavky s hlavičkou `Sec-Fetch-Storage-Access`, `DNT` nebo `Sec-GPC` se dříve považovaly za neznámé a cache je vynechala. Souběžné ukládání při načítání stránky nyní krátce čeká na zápis místo okamžitého vzdání. Adresa, jejíž položka cache čeká na obnovu úložiště, se online načte přímo z webu místo chyby 503. Odpovědi bez `Content-Length` se nadále neukládají, ale statistika je hlásí jako `response-unknown-length` místo MISS. Podmíněné požadavky prohlížeče (`If-None-Match`, `If-Modified-Since`) jdou dál přímo na web, aby se nezvyšoval přenos dat.

## Offline

Nejprve načtěte obsah online. Pak zvolte „Offline — pouze uložený obsah“. Proxy neotevírá odchozí spojení pro chybějící obsah, DNS/DoH, CONNECT, SOCKS5 ani WebSocket; MISS vrací HTTP 504. Přepnutí zavře existující spojení. Toto je režim HomeProxy, nikoli firewall celé přípojky.

Způsobilé čerstvé objekty a omezeně staré veřejné objekty lze číst z disku i po restartu. Maximální dovolené stáří po expiraci je nastavitelné, standardně 168 hodin. `must-revalidate`, `proxy-revalidate`, `s-maxage` a další pokyny vyžadující validaci mají přednost. Přihlášení, POST/API, licence nebo stránka vyžadující další serverový stav se uložením statických souborů nestanou offline aplikací.

Byte ranges se obsluhují z kompletního, vhodného uloženého těla: otevřený/suffix interval, 206/416 a `If-Range`. Verze 1.2.0 navíc skládá jednotlivé origin 206 fragmenty se shodným silným ETag, známou celkovou délkou, kompresí a variantou. Pokryté intervaly lze použít offline; mezera vrací 504. Plnou 200 odpověď lze vydat až po pokrytí všech bajtů. Konflikt obsahu zneplatní danou generaci. HEAD umí použít metadata uloženého GET, neposílá tělo a nezapočítává neodeslané bajty jako úsporu. Stejné vhodné downloady se slučují; zrušení a clear cache nemohou obnovit starou generaci.

Online revalidace používá ETag, případně Last-Modified. Bezpečná 304 obnoví metadata; změněná nebo soukromá odpověď starý objekt nahradí či zneplatní. Automatický fallback při chybě vyžaduje výslovný `stale-if-error` serveru a respektuje místní mez stáří. Platí pouze pro dovolené síťové chyby nebo 500/502/503/504, nikdy pro selhání TLS nebo přístupu.

Ve verzi 1.2.0 lze vhodnou veřejnou odpověď s `no-cache` nebo nulovým počátečním TTL uložit pro následnou online validaci. Každé další použití vyžaduje origin; offline vrací 504. Připnutí toto pravidlo nemění. Čerstvost může určovat také `Expires`; `Cache-Control`, `Age` a `Date` mají přednost. Původní bajty gzip/br zůstávají uložené v daném kódování, včetně rozsahů; klient musí tuto reprezentaci přijímat.

## Příprava obsahu ve verzi 1.2.0

Aktualizace používá nový klíč reprezentací a index `Vary`. Obsah z cache 1.1.5 je potřeba v 1.2.0 nejdříve znovu načíst online; před přechodem do offline režimu použijte přípravu obsahu a zkontrolujte jeho stav. Nastavení a CA se tímto přechodem nemažou.

V nastavení zadejte až 32 veřejných HTTP(S) URL, rozpočet 1–1024 MiB a volitelné připnutí. Jedna úloha stahuje postupně, lze ji zrušit a po restartu se automaticky neobnovuje. Přesměrování vyžaduje explicitní přidání cílové URL. Související CSS, obrázky či skripty je potřeba uvést samostatně; funkce nespouští JavaScript ani neprochází web.

Připnuté položky mají společný limit 25 % kapacity cache a chrání se před běžným LRU úklidem. Stav zvlášť ukazuje uložení, připnutí a aktuální použitelnost offline. Změna serverového obsahu připnutý záznam trvale zneplatní, ale zachová jeho referenci pro uvolnění; přístup ke staré verzi tím nevznikne. Výslovné vymazání cache odstraní i piny a historii přípravy.

Před online ověřováním existující cache se uloží trvalý ochranný záznam. Pokud během změny odpovědi selže disk nebo služba náhle skončí, dotčená rodina souborů se po restartu nepoužije. Piny zůstanou dostupné pro uvolnění. Nevyřešený stav lze odstranit výslovným vymazáním cache a novou přípravou online. Běžný dokončený přenos a restart tuto ochranu nezanechávají.

Serverové `Vary` omezuje reprezentaci na určité hlavičky. Obecná příprava posílá `Accept: */*` a `Accept-Encoding: identity`; položky s `Vary` proto konzervativně nedeklaruje jako použitelné pro libovolný prohlížeč. URL s query zůstává jen v běžící úloze; historie uchovává omezený popisek bez query a credentials. Cesta v popisku může obsahovat citlivý identifikátor, proto zadávejte veřejné adresy. Privátní JSON manifest má režim 0600.

CLI nabízí `homeproxy cache prepared`, `homeproxy cache prepare --file seznam.json`, `homeproxy cache cancel ID` a `homeproxy cache unpin KLÍČ`. Vstupní JSON má tvar `{"urls":["https://example.org/soubor.jpg"],"budgetMib":64,"pin":true}`. URL ani credentials se nepředávají jako samostatné CLI argumenty.

## Zařízení, filtry a přenosy

Profily mají vlastní přihlášení, rychlosti, denní/měsíční kvóty, domény a plány. Ověřené přihlášení poskytuje stabilní identitu při změně IP; ruční IP alias je volitelný a vyžaduje údržbu při DHCP změně. Časové plány používají pevný UTC posun; automatický přechod na letní čas se neprovádí. Interval přes půlnoc patří dni začátku.

Nové spojení s ověřeným přihlášením profilu bez IP aliasu při časovém zákazu, vyčerpané kvótě nebo nedostupné kvótové historii vrací úplnou HTTP 403 a zavře se. Chybné přihlášení vrací 407. Již přijaté spojení, IP alias nebo souběžná změna pravidel mohou způsobit okamžité uzavření bez HTTP odpovědi; zákaz přenosu zůstává účinný.

Doménový zákaz převažuje nad povolením. Povolení překoná reklamní filtr, ne kontrolu cílové IP ani ochranu cache. Importované doménové soubory lze aktualizovat bez vydání aplikace v UI nebo příkazem `homeproxy filter import --name domácí --file seznam.txt`. Podporované jsou domény, hosts a `||domain^`; regex, URL a kosmetická pravidla se odmítnou. Import je ruční, bez automatického síťového updateru. Stejný název nahradí celý seznam atomicky.

Historie ukládá součty podle profilu/IP, nikoli URL, query, cookies nebo hesla. `homeproxy history export --format csv --output history.csv` vytvoří nový soukromý soubor. Čistý stop/restart zachová kvóty. Pro profily s kvótami se před přenosem trvale rezervuje nejvýše 1 MiB kredit; po náhlém pádu se nevyúčtovaný kredit konzervativně započte do kvóty. Skutečné přenesené bajty se nevymýšlejí. Report odlišuje kredity a dluh po pádu; běžné součty bez kvót mají periodický checkpoint.

## PAC, nadřazená proxy a DNS

PAC je volitelné na `http://IP-počítače:HTTP-port/proxy.pac`, bez přihlašovacích údajů. Přímý fallback je zvlášť volitelný a může obejít HomeProxy pravidla/offline režim v klientovi; standardně je vypnutý. Aplikace, které PAC ignorují, je nutné nastavit jinak.

Nadřazené HTTP proxy se používají v uvedeném pořadí. Failover zkouší další při chybě spojení, nikoli při odmítnutí přístupu. Přímá trasa vyžaduje explicitní volbu. Přihlašování parent proxy probíhá po HTTP; patří do důvěryhodné sítě. SOCKS5 UDP s parent proxy se odmítne. Nejde o sloučení internetových přípojek.

Volitelný LAN DNS filtr nabízí UDP i TCP na zvolených soukromých adresách, standardně port 5353. Běžné síťové DNS používá 53, proto je potřeba ruční nastavení podporovaného routeru nebo oprávnění pro port 53. Automatické routerové/SQM/firewall změny se neprovádějí. DNS profily používají ruční IP aliasy, protože DNS neposkytuje proxy přihlášení. Vlastní DoH/VPN nebo přímé IP mohou doménový filtr obejít. DNS odpovědi jsou omezené TTL a zůstávají v paměti při přepnutí režimu; nepřežívají restart procesu.

## Google Play, YouTube a SmartTube

Tato implementace není univerzální cache stock Google Play ani YouTube/SmartTube. YouTube/SmartTube domény mají vestavěný bypass. Google Play aplikace může kontrolu TLS odmítat a neveřejná či přihlášená stahování nejsou způsobilá pro sdílenou cache; explicitní allowlist webu z toho univerzální Play cache neudělá. Certifikáty, autorizace, měnící se URL/varianty, aplikace odmítající CA a SABR POST/session přenosy brání obecnému offline výsledku.

Pro fyzický telefon/TV je stále nutný samostatný test konkrétní verze a aplikace. Lokální distribuce vlastních APK, lokální mediální knihovna nebo upravený player jsou jiné datové cesty; tato větev je nevydává za automatickou Play/video cache.
