# ADR-0001: Oprzeć VulnMgmt na forku DefectDojo, nie budować greenfield

- Status: Zaakceptowane
- Data: 2026-11-09
- Autorzy: michal.szuszkiewicz (decyzja), Claude Code (research + draft)

## Kontekst

CLAUDE.md (wersja pierwotna) zakładał nową aplikację Django budowaną od zera
("greenfield"), z własnym modelem domenowym (Asset, ScanImport, Finding,
Vulnerability, SSVCDecision, Exception, AuditEvent) i własną strukturą
`backend/apps/{assets,ingest,parsers,findings,vulns,enrichment,ssvc,workflow,
audit,reporting}`.

Przed napisaniem jakiegokolwiek kodu padło pytanie: czy oprzeć projekt o istniejące
open-source narzędzie do zarządzania podatnościami (DefectDojo lub SecObserve)
zamiast pisać to samo od zera. Rozważono dwie opcje pod kątem kryteriów
dojrzałości z CLAUDE.md §2 (aktywny rozwój, ≥3 lata historii, szeroka
społeczność, licencja, brak statusu archived) oraz zgodności z wymaganiami
domenowymi (SSVC, formaty importu z §5.1, model assetu z §6.3).

### Porównanie (dane z GitHub/docs, zweryfikowane 2026-11-09)

| Kryterium | DefectDojo | SecObserve |
|---|---|---|
| Licencja | BSD-3-Clause | BSD-3-Clause (wg README) |
| Gwiazdki / forki | ~5.2k / ~2k | 335 / 39 |
| Watchers | 199 | 3 |
| Commity | 16 166 (master) | 4 805 (dev) |
| Społeczność | Flagowy projekt OWASP, wielu maintainerów, wsparcie korporacyjne | Praktycznie jeden główny maintainer (release'y robi jedna osoba) — realne ryzyko bus-factor-1 |
| Stos | Django 5.2.17 + DRF 3.18.3, Celery + Valkey, Postgres | Django + DRF, React/TS frontend, Celery+Huey, Postgres/MySQL |
| SSVC | Brak | Brak |
| Priorytetyzacja | Severity z narzędzia + manualna korekta + EPSS (funkcja **Pro**, płatna) | Severity/CVSS-bt + EPSS + rule engine + risk acceptance z wygasaniem |
| Formaty z §5.1 | SARIF, Trivy, Nuclei, Semgrep, Burp (5 wariantów), ZAP, CycloneDX, SPDX, OpenVAS, Qualys; Nessus pod nazwą `tenable` | SARIF, CycloneDX generycznie + Trivy, Semgrep, ZAP, Checkov, Gitleaks; **brak Nessus i Burp** |
| Model assetu | Product_Type → Product → Engagement → Test → Finding; brak pól Exposure/Mission Impact/Safety Impact | Product Group → Product → Service → Branch; brak widocznych atrybutów ekspozycji/wpływu biznesowego |

Żadne z dwóch narzędzi nie implementuje SSVC (CERT/CC) jako drzewa decyzyjnego —
oba sprowadzają priorytetyzację do severity/CVSS/EPSS, co CLAUDE.md §13 explicite
zakazuje jako wynik końcowy ("Nie upraszczaj SSVC do jednej liczby/score'u"). To
automatycznie oznacza, że wybór którejkolwiek z tych baz wymaga **dobudowania
własnego silnika SSVC i modelu asset-context** niezależnie od wyboru — żadne z
nich nie daje tego "za darmo".

## Decyzja

Projekt **forkuje DefectDojo** (`DefectDojo/django-DefectDojo` → `ohanze/vulnmgmt`,
fork na GitHub z zachowaną historią i remote `upstream` tylko do `fetch`) i
rozwija go dalej, zamiast pisać nową aplikację od zera lub forkować SecObserve.

Powody:
1. **Dojrzałość i społeczność** — DefectDojo zdecydowanie przewyższa SecObserve na
   kryteriach z §2 (15× więcej gwiazdek, 66× więcej watcherów, wielu
   maintainerów vs. praktycznie jeden). SecObserve niesie realne ryzyko
   bus-factor-1, czego CLAUDE.md §2 explicite zabrania.
2. **Pokrycie formatów z §5.1** — DefectDojo ma już natywne parsery dla
   zdecydowanej większości priorytetowych formatów (SARIF, Trivy, Nuclei,
   Semgrep, Burp, ZAP, CycloneDX, SPDX, OpenVAS, Qualys), co eliminuje
   największy nakład pracy z §12 krok 3. SecObserve nie ma Nessus/Burp.
3. **Zgodność stosu** — Django 5.2.17, DRF + drf-spectacular, Celery + Valkey,
   Postgres — to dokładnie stos z CLAUDE.md §3, bez żadnych odstępstw w
   warstwie backendu.
4. **Istniejący model domenowy jest kompatybilny** — `Product`, `Finding`,
   `Risk_Acceptance` już mają pola, na których SSVC może się oprzeć
   (`cvssv3/v4`, `epss_score`, `known_exploited` czyli KEV, `cwe`, flagi
   `active/verified/false_p/duplicate/risk_accepted`). Nie trzeba modelować
   deduplikacji, cyklu życia findings ani workflow wyjątków od zera — trzeba je
   rozszerzyć o SSVC, nie zbudować równoległy system.
5. **Aktywny upstream** — możliwość ściągania poprawek bezpieczeństwa i nowych
   parserów z `upstream` bez utraty własnych zmian (fork, nie kopia).

## Konsekwencje

### Co trzeba zbudować samodzielnie (brak w DefectDojo)
- **Silnik SSVC** (CERT/CC, §6) — nowy moduł `dojo/ssvc/` wg konwencji repo
  (`models.py`, `services.py`, `queries.py`, `signals.py`, `ui/`, `api/`),
  czysta funkcja `(drzewo, punkty decyzyjne) -> decyzja`, drzewa jako dane
  (YAML/JSON), wersjonowanie, proweniencja, override z audytem.
- **Atrybuty asset-context na `Product`** — Exposure, Mission Impact, Safety
  Impact (§6.2–6.3) nie istnieją; trzeba dodać pola + migracje + wartości
  domyślne konserwatywne + flagę "niezweryfikowane".
- **CI bezpieczeństwa (§8)** — w `.github/workflows/` nie ma Trivy, Semgrep,
  SBOM, pip-audit, gitleaks. Trzeba dodać od zera; obecne workflow pokrywają
  tylko lint/testy/release/Helm.
- **Weryfikacja SSO/OIDC** — w tym checkoucie nie znaleziono działającej
  konfiguracji SAML/OIDC/LDAP (sprzeczne z ogólną wiedzą o DefectDojo —
  wymaga realnej weryfikacji przed dalszą pracą nad §3 "Auth").

### Odstępstwo od CLAUDE.md §3 wymagające decyzji
- **Frontend**: DefectDojo renderuje UI szablonami Django (server-rendered),
  nie ma SPA React/TS. CLAUDE.md §3 zakładał React 19 + TypeScript + Vite.
  To pozostaje **otwartą decyzją** (nie podjętą w tym ADR) — patrz TODO w
  CLAUDE.md. API (DRF + drf-spectacular) już istnieje, więc frontend SPA
  można dobudować później bez zmiany backendu.

### Zmiana architektury (§4)
- Nie ma `backend/apps/<domena>/` — jest jeden Django app `dojo` z ~45
  poddomenami (`dojo/<domena>/{models,admin,services,queries,signals,
  ui/*,api/*}.py`). Nowe moduły (`ssvc/`, rozszerzenia `product/` i
  `finding/`) muszą trzymać się tej konwencji, nie konwencji z pierwotnego
  CLAUDE.md.

### Bezpieczeństwo procesu
- `upstream` remote ma `push` ustawiony na `DISABLE` — nigdy nie wysyłamy
  nic do `DefectDojo/django-DefectDojo`.
- `AGENTS.md` i `.claude/skills/` forka są dokumentacją **upstreamu** (dla
  kontrybutorów do oryginalnego DefectDojo), nie instrukcjami dla tego forka.
  Oznaczone banerem w `AGENTS.md`; CLAUDE.md jest źródłem prawdy dla tego
  repo i ma pierwszeństwo przy konflikcie.

## Rozważane alternatywy

- **SecObserve jako baza** — odrzucone: mniejsza społeczność (bus-factor-1),
  brak Nessus/Burp, brak widocznych atrybutów asset-context, mimo bliższego
  stosu frontendowego (React/TS).
- **Czysty greenfield (plan pierwotny)** — odrzucone: oznaczałoby budowanie od
  zera dedup, cyklu życia findings, ~15 parserów, RBAC i workflow wyjątków —
  wszystko, co DefectDojo już ma przetestowane na produkcji przez wiele lat.
