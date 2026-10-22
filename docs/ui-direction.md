# HomeProxy UI direction

Locked 2026-08-23 after comparing three sketches. Use this, not the cream or light split.

## Feel
A dark household appliance on the computer running HomeProxy. One amber number answers “does it help?”.

**Dashboard stays this simple.** More settings will exist — blocking lists, compression strength, cache rules, per-device exceptions — but they live under Nastavení, never on Domov.

## Tokens
- Ground `#0b0c0e`
- Chrome `#16181c`
- Panel `#1b1e23`
- Line `#2a2d33`
- Ink `#ece7dc`
- Mute `#8b9099`
- Amber `#f0b429`
- Ads meter `#6ee7b7`
- Cache meter `#7dd3fc`
- Danger/sleep `#c9844a`

## Screens
1. **Domov** — today saved, three named presets, who is on. Do not add more controls here.
2. **Zařízení** — people and boxes; TV can do ads, not images.
3. **Výjimky** — bank, hovory, Netflix always direct.
4. **Nastavení / Settings** — the dense stuff: lists, strength, cache rules, sleep, certificate. Grouped, with the same screens in Czech and English.

## Cache sharing
Under Nastavení → Cache, not on Domov:
- Default: each device its own cache.
- Option: **Sdílet v celém domě** — one household pool so phones/PCs reuse the same public pages and images.
- Shared pool never includes logged-in, bank, health, or anything with cookies. Those stay per-device even when sharing is on.

## Copy rules
- No ports, filters, MITM, JPEG quality.
- Presets: reklamy Vypnuto / Mírné / Přísné; obrázky Ostřejší / Úspora / Maximum; cache 2 / 8 / 20 GB; cache sdílení Vypnuto / Sdílet v domě.
- Always say: the computer running HomeProxy must stay awake; films do not count; bank goes around.
