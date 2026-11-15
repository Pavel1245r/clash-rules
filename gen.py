#!/usr/bin/env python3
"""Собирает шаблон Clash/Mihomo из профиля Happ «RoscomVPN Whitelist».

Источник: https://github.com/hydraponique/roscomvpn-routing/blob/main/HAPP/WHITELIST.JSON
Результат: clash-whitelist.yaml — его по ссылке забирает 3x-ui (настройка subClashRules).

Логика как у Xray в Happ:
  * RouteOrder (например block-proxy-direct) — порядок групп правил;
  * DomainStrategy IPIfNonMatch — сначала все правила по доменам, потом по IP;
  * GlobalProxy true — всё, что не попало в правила, идёт через VPN.
Сами списки доменов/IP Mihomo качает напрямую с нашего сервера: он раз в сутки зеркалит их у автора (roscomvpn-geosite / roscomvpn-geoip).
"""
import json
import sys
import urllib.request

SRC = "https://raw.githubusercontent.com/hydraponique/roscomvpn-routing/main/HAPP/WHITELIST.JSON"
OUT = "clash-whitelist.yaml"
# Списки берутся с зеркала на своём сервере (его раз в сутки обновляет sync-clash-rules),
# чтобы клиенту не нужен был jsdelivr и уже работающий прокси.
GEOSITE = "https://woksonbokson.duckdns.org/rules/roscomvpn-geosite-{}.mrs"
GEOIP = "https://woksonbokson.duckdns.org/rules/roscomvpn-geoip-{}.mrs"
TARGET = {"block": "REJECT", "proxy": "PROXY", "direct": "DIRECT"}


def q(s):
    return json.dumps(s, ensure_ascii=False)  # строка YAML в двойных кавычках


def site_rule(entry, target, providers):
    if entry.startswith("geosite:"):
        name = entry.split(":", 1)[1]
        key = "site-" + name
        providers[key] = ("domain", GEOSITE.format(name))
        return f"RULE-SET,{key},{target}"
    for prefix, kind in (("domain:", "DOMAIN-SUFFIX"), ("full:", "DOMAIN"), ("regexp:", "DOMAIN-REGEX"),
                         ("keyword:", "DOMAIN-KEYWORD")):
        if entry.startswith(prefix):
            return f"{kind},{entry[len(prefix):]},{target}"
    return f"DOMAIN-SUFFIX,{entry},{target}"


def ip_rule(entry, target, providers):
    if entry.startswith("geoip:"):
        name = entry.split(":", 1)[1]
        key = "ip-" + name
        providers[key] = ("ipcidr", GEOIP.format(name))
        # частные адреса не резолвим, остальное — как IPIfNonMatch (резолв, если домен ни под что не попал)
        return f"RULE-SET,{key},{target}" + (",no-resolve" if name == "private" else "")
    kind = "IP-CIDR6" if ":" in entry else "IP-CIDR"
    cidr = entry if "/" in entry else entry + ("/128" if ":" in entry else "/32")
    return f"{kind},{cidr},{target},no-resolve"


def build(p):
    order = (p.get("RouteOrder") or "block-proxy-direct").split("-")
    providers, site_rules, ip_rules = {}, [], []
    for group in order:
        t = TARGET[group]
        name = group.capitalize()
        site_rules += [site_rule(e, t, providers) for e in p.get(name + "Sites", [])]
        ip_rules += [ip_rule(e, t, providers) for e in p.get(name + "Ip", [])]
    if p.get("DomainStrategy", "IPIfNonMatch") == "AsIs":
        ip_rules = [r if r.endswith("no-resolve") else r + ",no-resolve" for r in ip_rules]
    final = "PROXY" if str(p.get("GlobalProxy", "true")).lower() == "true" else "DIRECT"

    remote = p.get("RemoteDNSDomain") or f"https://{p.get('RemoteDns', '8.8.8.8')}/dns-query"
    domestic = p.get("DomesticDNSDomain") or f"https://{p.get('DomesticDns', '77.88.8.8')}/dns-query"
    fake_filter = ["rule-set:site-private"] if "site-private" in providers else []

    y = [f"# Собрано автоматически из {SRC}",
         f"# Профиль: {p.get('Name', '')}, LastUpdated: {p.get('LastUpdated', '')}. Не править вручную — см. gen.py.",
         ""]
    if p.get("DnsHosts"):
        y.append("hosts:")
        y += [f"  {q(k)}: {q(v)}" for k, v in p["DnsHosts"].items()]
        y.append("")
    y += ["dns:", "  enable: true", "  ipv6: false", "  use-hosts: true",
          # fake-ip всегда: без него Mihomo в режиме TUN видит только IP и правила по доменам не срабатывают
          "  enhanced-mode: fake-ip",
          "  fake-ip-range: 198.18.0.1/16"]
    if fake_filter:
        y += ["  fake-ip-filter:"] + [f"    - {f}" for f in fake_filter]
    y += ["  default-nameserver:", f"    - {domestic}", f"    - {remote}",
          "  proxy-server-nameserver:", f"    - {domestic}", f"    - {remote}",
          "  direct-nameserver:", f"    - {domestic}",
          "  nameserver:", f"    - {q(remote + '#PROXY')}", ""]
    y += ["sniffer:", "  enable: true", "  override-destination: false", "  parse-pure-ip: true",
          "  sniff:", "    HTTP:", "      ports: [80, 8080-8880]", "    TLS:", "      ports: [443, 8443]",
          "  skip-dst-address:"] + [f"    - {a}" for a in (
              "224.0.0.0/3", "10.0.0.0/8", "127.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12",
              "198.18.0.0/15", "169.254.0.0/16", "192.168.0.0/16", "fc00::/7", "fe80::/10")] + [""]
    y += ["proxy-groups:",
          "  - name: 🛡️ VPN", "    type: select", "    include-all: true", "    proxies:", "      - ⚡️ Авто",
          "    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Hijacking.png",
          "  - name: ⚡️ Авто", "    type: url-test", "    include-all: true", "    hidden: true",
          "    url: https://www.gstatic.com/generate_204", "    interval: 300", "    tolerance: 150",
          "  - name: PROXY", "    type: select", "    hidden: true", "    proxies:", "      - 🛡️ VPN", ""]
    y.append("rule-providers:")
    for key, (behavior, url) in providers.items():
        y += [f"  {key}:", "    type: http", f"    behavior: {behavior}", "    format: mrs",
              "    interval: 86400", "    proxy: DIRECT", f"    path: ./ruleset/{key}.mrs", f"    url: {url}"]
    y += ["", "rules:"] + [f"  - {r}" for r in site_rules + ip_rules] + [f"  - MATCH,{final}", ""]
    return "\n".join(y)


if __name__ == "__main__":
    src = sys.argv[1] if len(sys.argv) > 1 else SRC
    raw = open(src, encoding="utf-8").read() if not src.startswith("http") else \
        urllib.request.urlopen(src, timeout=30).read().decode("utf-8")
    text = build(json.loads(raw))
    try:
        old = open(OUT, encoding="utf-8").read()
    except FileNotFoundError:
        old = ""
    # LastUpdated в шапке меняется у автора часто — сравниваем без шапки, чтобы не плодить пустые коммиты
    body = lambda t: "\n".join(l for l in t.splitlines() if not l.startswith("#"))
    if body(old) == body(text):
        print("без изменений")
    else:
        open(OUT, "w", encoding="utf-8", newline="\n").write(text)
        print("обновлено:", OUT)
