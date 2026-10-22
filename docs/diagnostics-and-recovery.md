# Diagnostika a automatická obnova — HomeProxy 1.2.3

V aplikaci otevřete **Domov → Diagnostika a obnova → Exportovat diagnostiku**.
Aplikace uloží soubor `HomeProxy-diagnostika-….json` do **Stažených** a ukáže jeho
cestu. Tento soubor pošlete při hlášení problému. Terminál není potřeba.
Export zahrnuje současný stav a zachované automatické incidenty, takže jej lze
vytvořit i po samoobnově. Nic se automaticky neodesílá.

Report obsahuje domácí IP adresy, provozní čítače, počty a stáří spojení a výsledky
místních kontrol. Neobsahuje hesla, uživatelská jména, historii navštívených stránek,
obsah požadavků, privátní klíče ani certifikáty. Při nedostupné službě desktop uloží
výslovně označený částečný report. Ten nenahrazuje diagnostiku běžící služby.

## Co se kontroluje a obnovuje

Kontrola běží ve službě také při zavřeném okně. Každých 15 sekund ověřuje skutečnou
krátkou HTTP odpověď na místním listeneru. Po spuštění či změně konfigurace čeká
nejméně 30 sekund. **Tato kontrola nepotvrzuje dostupnost internetu, DNS, jednotlivých
webů ani připojení TV po síti.** Neukládá ani neodesílá provoz na veřejný kontrolní web.

Po třech po sobě jdoucích selháních se zachová incident. Obnova je povolená pouze
při souhlasných údajích o stále stejné proxy: volná kapacita a opakovaně neodpovídající
místní listener, nebo celkově zaplněná kapacita s opakovaně prokázanými příliš starými
nečinnými spojeními. Samotných 256 aktivních spojení, limit jednoho zařízení,
nedostupný poskytovatel internetu, kvóta či ruční zastavení nejsou příkazem k obnově.
Obsazené diagnostické zámky se označí jako nedostupné a nepovažují se za důkaz poruchy.

Obnovuje se runtime proxy uvnitř stejného daemonu. Uložené zapnutí, hesla, cache,
historie a kvóty se zachovávají. Ruční **Zastavit**, změna konfigurace a ukončení služby
zneplatní předchozí výsledky sond. Automatiku lze vypnout přepínačem v panelu a uložením
nastavení. Po obnově se znovu ověří místní odpověď.

Ochrana před smyčkou dovoluje nejvýše tři automatické pokusy za hodinu, s odstupem
nejméně deset minut. Rozpočet se ukládá i přes restart služby. Pokud se obnova nepodaří,
automatika se pozastaví; úspěšné ruční Spustit nebo uložení opraveného nastavení
dovolí nový dohled, ale nemaže časový rozpočet. Neúspěšný ruční zásah pozastavení neruší.
Pokud se nepodaří potvrdit bezpečné uložení incidentu nebo rozpočtu, zachová se
paměťová diagnostika a automatický restart se neprovede.
Zamrznutí celého procesu nebo jeho async runtime tímto vnitřním dohledem řešeno není.

## Dlouhý běh a kvóty — od 1.2.7

Chyba zápisu historie provozu, například při plném disku, už neblokuje kvótované
profily až do restartu služby. Profily s kvótou zůstanou do úspěšného uložení
zablokované (fail-closed), ale minutová údržba zápis zkouší znovu a po uvolnění
místa se historie i kvóty obnoví samy. Chyby načtení, formátu nebo kapacity historie
zůstávají blokující do zásahu správce. `homeproxy doctor` v obou případech vrací
exit 6 se skutečnou chybou historie. U chyby zápisu zkontrolujte volné místo
(`df -h /var`); poškozený soubor nebo překročená kapacita historie se uvolněním
místa neopraví.

Pro sledování, že YouTube a další aplikace nenarážejí na HTTPS kontrolu, hledejte
v aktivitě chyby `TLS-handshake-rejected` a `TLS-handshake-timeout`:

```sh
homeproxy --json status | jq '[.stats.activity[]|select(.error)|{host,error}]|group_by(.error,.host)|map({e:.[0].error,h:.[0].host,n:length})'
```

Opakující se chyby u jednoho hostu od stejného zařízení znamenají, že klient CA
nedůvěřuje; přidejte doménu do výjimek, nebo kontrolu pro ni nevybírejte.

### Jednoduchý health check

`scripts/homeproxy-healthcheck.py` (jen Python 3 stdlib, nic nemění) spustí
`homeproxy doctor` a `status`, ověří zdraví historie, volné místo na `/var` a
opakovaná selhání HTTPS kontroly u jednoho zařízení a hostu. Volitelně stáhne
`https://www.youtube.com/generate_204` přes proxy; adresu proxy (u LAN s přihlášením
včetně jména a hesla) čte jen z proměnné `HOMEPROXY_HEALTH_PROXY`, ne z argumentů.
Exit 0 = v pořádku, 1 = varování, 2 = porucha.

```sh
python3 scripts/homeproxy-healthcheck.py
HOMEPROXY_HEALTH_PROXY=http://127.0.0.1:17891 python3 scripts/homeproxy-healthcheck.py
```

Příklad výše používá loopback bez přihlášení. Adresu s heslem nepište do příkazové
řádky (zůstala by v historii shellu); uložte ji do souboru čitelného jen vámi
a načtěte ji, např. `set -a; . ~/.config/homeproxy-health.env; set +a`.

Pro pravidelný dohled jej lze spouštět uživatelským systemd timerem nebo cronem
(např. každých 15 minut) a sledovat nenulový exit v journalu. Instalace balíčku
timer nezakládá; je to vědomé rozhodnutí správce.

## Uložení pro správce

Daemon ukládá incidenty do svého state adresáře, v balíčku standardně
`/var/lib/homeproxy/diagnostics`. Adresář má oprávnění 0700 a soubory 0600;
desktop dostává report přes již autorizovaný lokální Unix socket. Export nečeká
na běžný řídicí mutex ani načtení provozní historie. Diagnostika má posledních
60 souhrnných vzorků, maximálně 10 incidentů / 20 MiB a 2 MiB na incident.
Každou minutu odstraňuje incidenty starší než sedm dní i při zdravém provozu.
Záznam použitý pro právě probíhající obnovu chrání do dokončení tohoto přechodu;
před další obnovou musí zachytit čerstvý stav.
Při chybě disku zůstává omezený paměťový záznam a stav uložení je vidět v aplikaci.

Příkazy pro správce: `homeproxy diagnostics status` a
`homeproxy --json diagnostics export`. GUI používá nativní zápis souboru,
nikoli pouze browserový download. Server a desktop balíčky musí mít stejnou verzi.

## Oprava nečinných HTTP spojení

Limit `tunnelIdleTimeoutSeconds` nově platí také pro obyčejný HTTP a HTTPS Inspect.
Obnovuje se při skutečném přenosu dat, nikoli podle celkového stáří spojení.
Uzavření uvolní kapacitu a nedokončenou origin/cache cestu. Aktivní dlouhý přenos
může pokračovat. Tím se opravuje lokálně reprodukovaná mezera z
analýzy hlášeného výpadku; bez provozních dat z postiženého počítače tím ještě
není potvrzena příčina konkrétního výpadku.

Reprodukční regrese: `scripts/test-linux-http-stall.py --expect-reclaimed`.
Skutečnou samoobnovu bez změn systémové služby ověřuje
`scripts/test-linux-diagnostics.py`, který pouze vlastnímu izolovanému daemonu
vloží testovací poruchu přijímání spojení a ověří soubor před opětovným bindem.

## English

Open **Home → Diagnostics and recovery → Export diagnostics**. The native app
saves a JSON file to Downloads and shows its path. Send that file when reporting an
issue; no terminal or automatic upload is required. It includes current state and
retained incidents, local IP addresses and counters, but no credentials, browsing
history, request contents or private keys. An unavailable daemon produces a clearly
partial desktop report.

The daemon supervises its local HTTP listener independently of the open window.
This does not test WAN access, DNS, individual sites or a TV's network connection.
Repeated, evidenced local failure is captured before a guarded runtime recovery.
Manual Stop is preserved; legitimate capacity/policy limits do not trigger recovery.
Recovery attempts are limited to three per hour and at least ten minutes apart,
persisted across daemon restarts. Failed recovery suspends the watchdog. Missing
durable incident or budget storage permits memory diagnostics but prevents automatic recovery.
Expired reports are removed periodically during healthy operation; the incident
used by a recovery remains protected through that transition.
HTTP and inspected HTTPS now release connections after configured byte inactivity,
while continuously active streams retain unlimited total lifetime.
