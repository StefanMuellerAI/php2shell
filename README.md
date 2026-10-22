# PHP2Shell-Check

Selbstcheck für Website-Betreiber zu den PHP-Lücken CVE-2026-109618 und CVE-2026-109619.

- `index.html` – die Seite (Website-Check oder Version eintippen, Ampel, Fahrplan, Mail-Vorlage)
- `api/check.js` – Prüf-Funktion: ruft die Startseite einmal per GET ab, folgt bis zu 5 Weiterleitungen und liest aus, was der Server über PHP verrät. Sperrt interne Adressen, fremde Ports und Zugangsdaten in URLs, speichert und loggt keine Adressen.
- `api/_analyze.js` – Auswertung der Antwort (Header, Cookie-Namen, HTML-Merkmale)
- `vercel.json` – Region Frankfurt (fra1), Sicherheits-Header

## Veröffentlichen

```
cd php2shell-check
npx vercel --prod
```

Beim ersten Mal: Scope „StefanAI“ wählen, neues Projekt `php2shell-check` anlegen, die erkannten Einstellungen übernehmen (kein Framework, kein Build).

## Danach

- Datenschutzerklärung auf stefanai.de um Vercel als Hosting-Anbieter dieses Tools ergänzen.
- Eigene Subdomain (z. B. php-check.stefanai.de) im Vercel-Projekt unter Domains hinzufügen und den angezeigten CNAME beim DNS-Anbieter setzen.
