# clash-rules

Шаблон маршрутизации Clash/Mihomo, повторяющий профиль Happ **RoscomVPN Whitelist**
([источник](https://github.com/hydraponique/roscomvpn-routing/blob/main/HAPP/WHITELIST.JSON)).

- `clash-whitelist.yaml` — шаблон; в 3x-ui указывается в «Подписка → Clash → правила» (`subClashRules`) ссылкой
  `https://raw.githubusercontent.com/Pavel1245r/clash-rules/main/clash-whitelist.yaml`.
- `gen.py` — собирает шаблон из профиля Happ.
- `.github/workflows/sync.yml` — раз в сутки пересобирает шаблон и сохраняет, если профиль у автора изменился.

Правила: блок — слежка Windows, торренты, реклама; напрямую — локальные адреса и белый список РФ; остальное — через VPN.
Списки доменов и IP Mihomo сам обновляет раз в сутки с jsDelivr.
