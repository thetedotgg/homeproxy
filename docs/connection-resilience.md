# Dlouhodobý provoz a obnova spojení

Úprava řeší držení kapacity nečinnými tunely a zastavení listenerů po přechodné
chybě při přijímání socketu. Nevkládá pravidelný restart počítače ani proxy.
Z výpadku konkrétní Android TV zatím nemáme diagnostiku jejího počítače;
stejný příznak se podařilo lokálně reprodukovat zaplněním limitu spojení.
To dokládá problém v této cestě, nikoli jistotu příčiny každého klientského výpadku.

## Životnost přenosu

- TCP keepalive se nastavuje na přijatém i odchozím TCP socketu: 60 sekund
  do první sondy, 20 sekund mezi sondami, 3 nezodpovězené sondy. Na podporovaných
  systémech pomáhá odhalit zmizelého protějška; přesný čas uzavření určuje OS.
  Selhání volitelného nastavení má vlastní diagnostický čítač a nezastaví proxy.
- Opaque HTTP CONNECT, SOCKS5 TCP a WebSocket relaye končí po **30 minutách
  souvislé nečinnosti**. Kladný počet přečtených či zapsaných bajtů v kterémkoli
  směru obnovuje časovač. Celkový věk spojení není omezený. TCP sondy,
  readiness, EOF a flush nejsou aplikační přenos.
- Přenos používá jedinou kopírovací future; kontrola časovače nepřerušuje
  kopírování ani nezahazuje rozpracované buffery. Zrušení či skutečné vypršení
  nečinnosti může zahodit čekající data a uzavírá oba sockety.
- Aplikace, která nechává zdravý tunel zcela potichu déle než limit, jej musí
  znovu otevřít. Pro takové použití lze limit prodloužit. Keepalive sám neodstraní
  zdravé zapomenuté spojení. HTTP hlavičky, TLS handshake a čekání na CONNECT
  upgrade mají samostatný krátký limit; SOCKS UDP si zachovává vlastní pravidla.

Nové pole nastavení `tunnelIdleTimeoutSeconds` má výchozí hodnotu `1800`
a povolený rozsah `60` až `86400`. Starší konfigurace bez tohoto pole se načte
s výchozí hodnotou; uložené přihlašovací údaje, CA a ostatní nastavení se zachovají.
Na Linuxu lze použít například:

```sh
homeproxy config set tunnelIdleTimeoutSeconds 3600
```

Uložení konfigurace používá dosavadní aplikaci změn a může jednorázově znovu
otevřít listenery. Průběžný provoz žádný plánovaný restart neprovádí.

## Přijímání spojení a obnova služby

Přechodné chyby `accept`, včetně vyčerpání deskriptorů či síťových bufferů,
se opakují s prodlevou od 50 ms do nejvýše 1 sekundy. Existující tunely se
zachovají a ruční Stop přeruší i čekání mezi pokusy. Chyby jednotlivých
listenerů se sledují odděleně: úspěšný HTTP accept nesmaže chybu SOCKS listeneru.
Trvalá chyba se nezamlčí a zůstane viditelná ve stavu.

Linux daemon má dosavadní obnovu uloženého zapnutého stavu každých 5 sekund.
Stejnou obnovu nově provádí také embedded desktop na Windows. Běžící proxy
zůstává nedotčená; obnovuje se pouze zastavená proxy s uloženým `enabled: true`.
Ruční Stop ukládá `false`, proto ji údržba sama nezapne. Ukončení aplikace
zruší údržbu i pokus čekající na stavový zámek, přičemž uložené zapnutí zůstane
zachované pro příští spuštění aplikace.

Limity zůstávají 256 spojení celkem a 128 na IP. Živá evidence je svázaná
s posledním vlastníkem povolení spojení, včetně HTTP upgrade. Neodvozuje se
z omezené historie aktivit a promazání historie ji neodstraní.

## Diagnostika

Linux `homeproxy --json status` nově obsahuje v `stats`:

| Pole | Význam |
|---|---|
| `activeConnections`, `connectionLimit`, `connectionLimitPerPeer` | Skutečně držená kapacita a její limity |
| `liveConnections` | ID, IP klienta, protokol, stáří a doba bez kladného I/O |
| `idleConnectionsClosed` | Kumulativní počet tunelů uzavřených kvůli nečinnosti |
| `keepaliveConfigurationFailures` | Kumulativní selhání nastavení TCP keepalive |
| `listenerRuntimeError`, `listenerRuntimeErrors` | Aktuální chyba přijímání a kumulativní počet chyb |

`homeproxy doctor` hlásí degradaci (exit 6), pokud zapnutá proxy neběží,
listener má aktuální chybu, je vyčerpána celková kapacita či kapacita
jedné IP, nebo (od 1.2.7) historie provozu není zdravá a blokuje kvóty. Historický počet odmítnutí nebo již opravených chyb sám degradaci
nezpůsobuje. Stav `running` znamená živý runtime, není zárukou dostupnosti
vzdáleného internetu či všech aplikací TV.
Ruční Stop odstraní aktuální chybu ukončených listenerů; kumulativní počet
chyb zůstává zachovaný pro pozdější diagnostiku.

## Regresní ověření

Rust testy pokrývají inactivity timer, kladné I/O v obou směrech, half-close,
backpressure a zachování bufferů, přednost zrušení, skutečné hodnoty Linux
keepalive, živou evidenci po evikci/promazání historie, chyby více listenerů,
konfigurační migraci, doctor a obnovu zapnutého Engine po neúspěšném bindu.
Integrační testy používají skutečné CONNECT, SOCKS TCP a WebSocket sockety;
krátký timeout je pouze v přímém testovacím fixture, produkční validace zůstává.

Pro test skutečného Linux daemonu slouží `scripts/test-linux-resilience.py`.
Test má soukromý dočasný profil a lokální parent proxy, která sama nikam
nepřipojuje. Adresa veřejného cíle je pouze text v CONNECT požadavku; veškerý
přenos zůstává na hostu. Vyčerpání deskriptorů se omezuje jen na testovací
podproces, nikdy na host nebo instalovanou službu.

```sh
cargo build --locked --offline -p homeproxy-service -p homeproxy-cli
python3 scripts/test-linux-resilience.py --bin-dir target/debug --output-dir /tmp/homeproxy-resilience-qa
```

Toto ověření nenahrazuje fyzickou Android TV, několikadenní běh u klienta,
čerstvé nasazení instalačního balíčku ani nativní Windows runtime. Změna DHCP
adresy, spánek hostitele, firewall a přetrvávající problém historie/kvót mohou
vyžadovat samostatnou diagnózu. Listener se nepřepíná na wildcard adresu,
autentizace, kvóty a ochrana soukromých cílů zůstávají platné.
