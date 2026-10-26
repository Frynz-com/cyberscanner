# Test-Fixtures

Anonymisierte, gespeicherte Antworten echter Werkzeuge/APIs. Domains wurden durch
`kunde-beispiel.de` ersetzt, IP-Adressen durch Dokumentations-/Beispieladressen,
E-Mail-Aliase durch Platzhalter. Formate entsprechen den Originalausgaben:

- `subfinder.jsonl` – Ausgabe von `subfinder -d <domain> -silent -oJ` (v2.17)
- `internetdb-cdn.json` – echte Antwort für 1.1.1.1 (öffentlicher Resolver); `internetdb-exposed.json` – synthetisches Beispiel im Originalformat (Dokumentations-IP 198.51.100.23)
- `hibp-breaches.json` – echte öffentliche Breach-Metadaten (/api/v3/breaches, Auszug); `hibp-breacheddomain.json`, `hibp-subscribeddomains.json` – synthetische Beispiele im dokumentierten Format (keine echten Personen)
- `nuclei.jsonl` – Beispiel im Format von `nuclei -jsonl` inkl. Treffer außerhalb des Scopes und defekter Zeile
- `crtsh.json` – Ausgabe von https://crt.sh/?q=%25.<domain>&output=json
- `hudsonrock-domain.json` – echte Antwort des kostenlosen Hudson-Rock-OSINT-Endpunkts (Domain anonymisiert); enthält nur Zählwerte und Login-URLs, keine Zugangsdaten
- `hudsonrock-clean.json` – Antwortformat für eine Domain ohne Treffer
- `ransomwarelive-search.json` – Format von `api.ransomware.live/v2/searchvictims/<begriff>`, Einträge fiktiv ersetzt
