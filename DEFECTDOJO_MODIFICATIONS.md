# Modyfikacje istniejącego kodu DefectDojo

Ten plik jest dziennikiem **wyłącznie** zmian w plikach, które istniały w
DefectDojo przed tym forkiem (`ohanze/vulnmgmt`). Nowe pliki/moduły (np. cały
`dojo/ssvc/`, nowe migracje) **nie są tu wpisywane** — to dodatki, nie
modyfikacje; ich historia żyje w `git log` i commitach danej funkcji.

Cel: (1) dać jedno miejsce do przeglądu przed `git merge upstream/dev` — każdy
wpis tu to potencjalne źródło konfliktu merge'a; (2) wymusić, żeby zmiana w
istniejącym pliku DefectDojo była świadomą decyzją z uzasadnieniem, nie
przypadkowym efektem ubocznym. Reguła, która to wymusza: **CLAUDE.md §13,
"Minimalna integracja w gotowe rozwiązania"**.

Każdy wpis: plik, co się zmieniło (precyzyjnie, nie "dodano SSVC"), dlaczego,
czy to czysto addytywne (bez usunięcia/przepisania istniejącej linii), commit.

---

## `dojo/models.py`

**Zmiana:** +1 linia — `from dojo.ssvc.models import SSVCDecision # noqa: E402, F401 -- re-export`,
wstawiona po istniejącej linii `from dojo.risk_acceptance.models import Risk_Acceptance`.

**Dlaczego:** Ten plik jest agregatorem re-eksportów modeli domenowych
(`from dojo.models import X` używane w całym repo) — każda domena ma tu swój
wpis (zob. `Risk_Acceptance`, `Tool_Product_History` bezpośrednio nad/pod tą
linią). `SSVCDecision` potrzebuje tego samego wpisu, żeby `dojo.auditlog`,
`dojo.admin` i reszta kodu mogły go znaleźć tą samą drogą co inne modele.

**Addytywne:** Tak — zero zmian w istniejących liniach.

**Commit:** `466bc8847` (feat(ssvc): add SSVCDecision model + Finding integration layer)

---

## `dojo/product/models.py`

**Zmiana:** +88 linii:
- import `from dojo.ssvc import constants as ssvc_constants`
- 4 nowe pola: `ssvc_exposure`, `ssvc_mission_impact`, `ssvc_safety_impact`
  (nullable, `choices=`), `ssvc_context_verified` (`BooleanField`, domyślnie `False`)
- metoda `_resolve_ssvc_field()` + 6 property (`effective_ssvc_exposure`,
  `effective_ssvc_exposure_source`, analogicznie dla `mission_impact`/`safety_impact`)
- metoda `ssvc_asset_context()` (wszystkie 3 rozwiązania w jednym wywołaniu —
  dodana w poprawce po code review, żeby nie liczyć tego samego dwukrotnie)

**Dlaczego:** CLAUDE.md §6.3 wymaga tych atrybutów na `Product` dla silnika
SSVC (ekspozycja, wpływ na misję, wpływ na bezpieczeństwo) — żaden nie
istniał. Wartości domyślne konserwatywne i dziedziczenie z `Product_Type`
też są wymogiem z tego paragrafu.

**Addytywne:** Tak — zero zmian w istniejących polach/metodach `Product`.

**Commity:** `9026d4086` (pola), `466bc8847` (refaktor properties + `*_source`),
`3c81ab2cf` (`ssvc_asset_context()`, poprawka po code review)

---

## `dojo/product_type/models.py`

**Zmiana:** +23 linie: import `ssvc_constants` + `gettext as _`, 3 nowe pola
(`ssvc_exposure`, `ssvc_mission_impact`, `ssvc_safety_impact`) — domyślne
organizacyjne, dziedziczone przez `Product`, które nie ustawiły własnych.

**Dlaczego:** CLAUDE.md §6.3 — "dziedziczenie z Product_Type → Product
(istniejąca hierarchia — użyj jej, nie wymyślaj nowej)".

**Addytywne:** Tak.

**Commit:** `9026d4086`

---

## Efekt poboczny: `dojo/db_migrations/0307_remove_product_insert_insert_and_more.py`

Nie jest to zmiana *pliku* DefectDojo (to nowy plik migracji), ale warto
odnotować: `makemigrations` wygenerował tu drop + recreate triggerów
`pgtrigger` na `product`/`product_type`, bo te modele są już objęte
`pghistory.track(..., AnyChange(...))` (zob. `dojo/auditlog/services.py`) —
dodanie pola do śledzonego modelu wymusza przebudowę triggera, który
kopiuje wiersz do tabeli `*_event`. To w pełni automatyczny, wygenerowany
skutek dodania pól wyżej, nie ręczna ingerencja w logikę audytu.

---

## `dojo/vulnerability/models.py`

**Zmiana:** +2 linie — import `from dojo.validators import cvss3_validator` oraz jedno nowe
pole na `Vulnerability`: `cvssv3_vector` (`TextField`, nullable, `validators=[cvss3_validator]`,
ten sam walidator, który już chroni `Finding.cvssv3`).

**Dlaczego:** CLAUDE.md §7 wymaga wzbogacania wektorem CVSS z NVD API 2.0. `Vulnerability` to
istniejący w DefectDojo globalny rejestr per-CVE (opisany we własnym docstringu jako "(future)
enrichment registry", z już istniejącymi kolumnami `epss_score`/`known_exploited`/`kev_date`/
`enrichment_updated` czekającymi na wypełnienie) — brakowało mu tylko kolumny na CVSS, bo
wcześniej nic go nie zapisywało. Nowy moduł `dojo/vuln_enrichment/` (dodatek, nie modyfikacja)
wypełnia wszystkie te kolumny i projektuje wynik na `Finding.epss_score`/`known_exploited`/
`kev_date`/`cvssv3` (już istniejące pola `Finding`, zero zmian w `dojo/finding/models.py`).

**Addytywne:** Tak — zero zmian w istniejących polach/metodach `Vulnerability`.

**Commit:** (ten branch, `feature/ssvc-enrichment`)

---

## Czego NIE dotknięto

Dla jasności zakresu: żadne zmiany w widokach, serializerach DRF, szablonach,
parserach (`dojo/tools/`), RBAC (`dojo/authorization/`), istniejących testach,
ani w logice migracji innej niż wyżej. `ProductSerializer`/`ProductTypeSerializer`
używają `exclude=`/`fields = "__all__"`, więc nowe pola na `Product`/`Product_Type`
trafiły do `/api/v2/products/`/`/api/v2/product_types/` bez jednej linii zmiany
w serializerach — to nie jest wpis tutaj, bo nic się w tych plikach nie zmieniło.
