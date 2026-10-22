## HomeProxy {{VERSION}}

**Česky**

- **Windows 10/11 (x64):** stáhněte [HomeProxy-Setup-x64.exe](https://github.com/{{REPOSITORY}}/releases/download/{{TAG}}/HomeProxy-Setup-x64.exe) a spusťte ho. Pokud Windows SmartScreen zobrazí varování, ověřte, že soubor pochází z této stránky, a zvolte **Další informace → Přesto spustit**.
- **Ubuntu 22.04 a novější (amd64):** stáhněte [HomeProxy-Ubuntu-amd64.tar.gz](https://github.com/{{REPOSITORY}}/releases/download/{{TAG}}/HomeProxy-Ubuntu-amd64.tar.gz) a v terminálu spusťte:

  ```sh
  tar -xzf HomeProxy-Ubuntu-amd64.tar.gz
  ./HomeProxy-Ubuntu-amd64/install.sh
  ```

  Instalátor zkontroluje, že se balíčky stáhly celé, nainstaluje službu i aplikaci a přidá vás do skupiny `homeproxy-admin`. Potom se odhlaste a znovu přihlaste.

**English**

- **Windows 10/11 (x64):** download [HomeProxy-Setup-x64.exe](https://github.com/{{REPOSITORY}}/releases/download/{{TAG}}/HomeProxy-Setup-x64.exe) and run it. If Windows SmartScreen shows a warning, make sure the file came from this page and choose **More info → Run anyway**.
- **Ubuntu 22.04 or newer (amd64):** download [HomeProxy-Ubuntu-amd64.tar.gz](https://github.com/{{REPOSITORY}}/releases/download/{{TAG}}/HomeProxy-Ubuntu-amd64.tar.gz) and run in a terminal:

  ```sh
  tar -xzf HomeProxy-Ubuntu-amd64.tar.gz
  ./HomeProxy-Ubuntu-amd64/install.sh
  ```

  The installer checks that the packages downloaded intact, installs the service and the app and adds you to the `homeproxy-admin` group. Sign out and back in afterwards.

Checksums for all files / Kontrolní součty všech souborů: [SHA256SUMS.txt](https://github.com/{{REPOSITORY}}/releases/download/{{TAG}}/SHA256SUMS.txt) (`sha256sum --check --ignore-missing SHA256SUMS.txt`).

To confirm the files were built by this repository's release workflow / Původ souborů z release workflow tohoto repozitáře ověříte: `gh attestation verify <file> --repo {{REPOSITORY}}`.
