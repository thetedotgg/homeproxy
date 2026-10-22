# Připojení zařízení pomocí QR

HomeProxy 1.2.1 usnadňuje instalaci veřejného CA certifikátu. QR vede na místní průvodce na vybrané LAN adrese a portu proxy. Telefon musí být na stejné důvěryhodné síti; pro otevření průvodce zatím nepotřebuje nastavenou proxy. Hlavní návody jsou Android a Windows, další volby zahrnují Apple a ostatní zařízení.

## Datová cesta a hranice důvěry

- Průvodce, DER certifikát a root-only Apple profil jsou veřejné read-only odpovědi na existujícím vybraném LAN listeneru. Neobsahují heslo, soukromý klíč, správu zařízení ani celý stav služby. Zachovávají omezení peerů, počet spojení a zákaz zařízení.
- V HTTP URL je pouze místní adresa, port, jazyk a SHA-256 připravené veřejné CA. Otisk brání nechtěnému použití starého QR po změně CA; neověřuje samotnou HTTP stránku proti aktivnímu útočníkovi.
- Původ certifikátu je nutné ověřit porovnáním SHA-256 skutečně staženého/importovaného DER certifikátu v důvěryhodném systémovém nástroji s otiskem na počítači s HomeProxy. Text na HTTP stránce není důkaz. Alternativou je důvěryhodný přenos veřejného certifikátu z tohoto počítače.
- Instalace certifikátu, potvrzení systémové důvěry a nastavení ruční proxy jsou oddělené kroky. Návštěva průvodce ani stažení nic z toho automaticky nepotvrdí. Některé aplikace vlastní CA nepřijímají.
- Stávající autentizace proxy a původní chráněné stažení přes homeproxy.test zůstávají oddělené od těchto tří lokálních veřejných odpovědí.

## Ověření změny

Kontroly zahrnují Host/URI/metody/query, zákaz zařízení, vypnutou LAN a chybějící CA, starý QR, totožné DER bajty ve všech exportech, zachování 407 pro běžnou proxy, dekódování QR nezávislým dekodérem a skutečné stažení bez předchozí konfigurace proxy. Mobilní rozměry prohlížeče samy nepotvrzují instalaci certifikátu na fyzickém telefonu.

## Závislosti a návody

QR vzniká lokálně pomocí [qrcode-generator](https://github.com/kazuhikoarase/qrcode-generator), verze 2.0.4, MIT, bez runtime závislostí a bez instalačních skriptů. Žádná služba pro generování QR nedostává adresu ani údaje zařízení.

- [Android: postup testu instalace CA v AOSP](https://android.googlesource.com/platform/cts/%2B/35dfb1c0b8d%5E%21/) — v nastavení instalace certifikátu vybrat typ CA; názvy nabídek závisí na výrobci a verzi.
- [Android: důvěra aplikací v uživatelské CA](https://developer.android.com/privacy-and-security/security-config) — aplikace mohou používat vlastní pravidla důvěry.
- [Apple: ruční potvrzení SSL/TLS důvěry](https://support.apple.com/en-us/102390).
- [Apple: jediný root certificate payload](https://developer.apple.com/documentation/devicemanagement/certificateroot).
- [Windows: certutil a SHA-256 souboru](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil).
