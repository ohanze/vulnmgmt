Ustalenie priorytetu obsługi podatności 

1. Priorytet obsługi podatności wyznacza proces oparty o drzewo decyzyjne 
2. Wartości punktów decyzyjnych przedstawia poniższa tabela:


| Punkt decyzyjny                   | Wartości                         | Kryterium                                                                                                                                                                                                                                                                                 |
| --------------------------------- | -------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Eksploitacja podatności           | Brak / Publicz PoC / Aktywna     | Brak – brak dowodów;  <br><br>Publiczny PoC – publiczny kod lub szczegółowy opis metody;  <br><br>Aktywna – wiarygodne informacje na temat wykorzystywania                                                                                                                                |
| Możliwość automatyzacji           | Tak/Nie                          | Tak – atakujący może zautomatyzować rozpoznanie, wykorzystanie i przejęcie bez interakcji użytkownika                                                                                                                                                                                     |
| Wpływ techniczny                  | Częściowy / Całkowity            | Całkowity – atakujący zdobywa pełną kontrolę nad komponentem lub pełne ujawnienie jego informacji                                                                                                                                                                                         |
| Ekspozycja sieciowa               | Lokalna / Kontrolowana / Otwarta | Lokalna - Usługa osiągalna tylko lokalnie, nie osiągalna z sieci biurowej. Usługi nie mają dostępu do Internetu. <br><br>Kontrolowana - Dostęp sieciowy ograniczony technicznie (odrębny segment, VPN, reguły firewall) <br><br>Otwarta - Dostęp z Internetu, DMZ lub z sieci niezaufanej |
| Istotność systemu dla organizacji | Niska/ Średnia / Wysoka          | Złożenie wpływu na misję i wpływu na bezpieczeństwo                                                                                                                                                                                                                                       |
5. Istotność systemu dla organizacji ustalane jest na podstawie wpływu na misję oraz wpływu na bezpieczeństwo. 
6. Wpływ na misję określa, w jakim stopniu dany system jest ważny dla realizacji najważniejszych zadań organizacji. Wpływ na misję może przyjąć następujące wartości: 
	1. Minimalny – System nie wspiera kluczowych procesów. Jego awaria jest niekomfortowa, ale nie utrudnia realizacji głównych zadań organizacji.;  
	2. Wspomagający– System pomaga w realizacji kluczowych procesów, ale można je wykonywać także innymi metodami, choć wolniej lub mniej wygodnie.  
	3. Kluczowy – System jest niezbędny do realizacji podstawowych zadań organizacji. Jego awaria powoduje zatrzymanie lub poważne zakłócenie działalności. 
7. Wpływ na bezpieczeństwo  może przyjąć następujące wartości: 
    1. Brak – brak wpływu na bezpieczeństwo 
    2. Znaczący– wpływ pośredni lub „Nie ustalono” 
    3. Istotny– wpływ bezpośredni.  
8 . Na podstawie wartości ustalonych w powyższych punktach ustalana jest wartość istotności systemu dla organizacji według poniższej tabeli: 
    
|                                         |         |          |         |
| --------------------------------------- | ------- | -------- | ------- |
| Wpływ na misję/ Wpływ na bezpieczeństwo | Brak    | Znaczący | Istotny |
| Minimalny                               | Niska   | Średnia  | Wysoka  |
| Wspomagający                            | Średnia | Wysoka   | Wysoka  |
| Kluczowy                                | Wysoka  | Wysoka   | Wysoka  |
Drzewo postępowania

**Legenda wyników:** ND – Natychmiastowe działanie · OP – Obsługa priorytetowa · M* – Monitorowanie* · M – Monitorowanie

| Eksploatacja podatności | Możliwość automatyzacji | Wpływ techniczny | Ekspozycja sieciowa | Istotność systemu dla organizacji: Niska | Istotność systemu dla organizacji: Średnia | Istotność systemu dla organizacji: Wysoka |
| ----------------------- | ----------------------- | ---------------- | ------------------- | ---------------------------------------- | ------------------------------------------ | ----------------------------------------- |
| Brak                    | Nie                     | Częściowy        | Lokalna             | M                                        | M                                          | M                                         |
| Brak                    | Nie                     | Częściowy        | Kontrolowana        | M                                        | M                                          | M                                         |
| Brak                    | Nie                     | Częściowy        | Otwarta             | M*                                       | M*                                         | M*                                        |
| Brak                    | Nie                     | Całkowity        | Lokalna             | M                                        | M                                          | M                                         |
| Brak                    | Nie                     | Całkowity        | Kontrolowana        | M                                        | M                                          | M*                                        |
| Brak                    | Nie                     | Całkowity        | Otwarta             | M*                                       | M*                                         | OP                                        |
| Brak                    | Tak                     | Częściowy        | Lokalna             | M                                        | M                                          | M*                                        |
| Brak                    | Tak                     | Częściowy        | Kontrolowana        | M                                        | M                                          | OP                                        |
| Brak                    | Tak                     | Częściowy        | Otwarta             | M*                                       | M*                                         | OP                                        |
| Brak                    | Tak                     | Całkowity        | Lokalna             | M                                        | M                                          | M*                                        |
| Brak                    | Tak                     | Całkowity        | Kontrolowana        | M                                        | M                                          | OP                                        |
| Brak                    | Tak                     | Całkowity        | Otwarta             | M*                                       | M*                                         | OP                                        |
| Publiczny PoC           | Nie                     | Częściowy        | Lokalna             | M                                        | M                                          | M                                         |
| Publiczny PoC           | Nie                     | Częściowy        | Kontrolowana        | M                                        | M                                          | M*                                        |
| Publiczny PoC           | Nie                     | Częściowy        | Otwarta             | M*                                       | M*                                         | OP                                        |
| Publiczny PoC           | Nie                     | Całkowity        | Lokalna             | M                                        | M                                          | M*                                        |
| Publiczny PoC           | Nie                     | Całkowity        | Kontrolowana        | M                                        | M*                                         | OP                                        |
| Publiczny PoC           | Nie                     | Całkowity        | Otwarta             | M*                                       | OP                                         | ND                                        |
| Publiczny PoC           | Tak                     | Częściowy        | Lokalna             | M                                        | M                                          | M*                                        |
| Publiczny PoC           | Tak                     | Częściowy        | Kontrolowana        | M                                        | M                                          | OP                                        |
| Publiczny PoC           | Tak                     | Częściowy        | Otwarta             | M*                                       | M*                                         | ND                                        |
| Publiczny PoC           | Tak                     | Całkowity        | Lokalna             | M                                        | M                                          | M*                                        |
| Publiczny PoC           | Tak                     | Całkowity        | Kontrolowana        | M                                        | M*                                         | OP                                        |
| Publiczny PoC           | Tak                     | Całkowity        | Otwarta             | M*                                       | OP                                         | ND                                        |
| Aktywna                 | Nie                     | Częściowy        | Lokalna             | M*                                       | M*                                         | M*                                        |
| Aktywna                 | Nie                     | Częściowy        | Kontrolowana        | M*                                       | M*                                         | OP                                        |
| Aktywna                 | Nie                     | Częściowy        | Otwarta             | M*                                       | M*                                         | ND                                        |
| Aktywna                 | Nie                     | Całkowity        | Lokalna             | M*                                       | M*                                         | OP                                        |
| Aktywna                 | Nie                     | Całkowity        | Kontrolowana        | M*                                       | OP                                         | ND                                        |
| Aktywna                 | Nie                     | Całkowity        | Otwarta             | M*                                       | ND                                         | ND                                        |
| Aktywna                 | Tak                     | Częściowy        | Lokalna             | M*                                       | M*                                         | OP                                        |
| Aktywna                 | Tak                     | Częściowy        | Kontrolowana        | OP                                       | OP                                         | ND                                        |
| Aktywna                 | Tak                     | Częściowy        | Otwarta             | ND                                       | ND                                         | ND                                        |
| Aktywna                 | Tak                     | Całkowity        | Lokalna             | M*                                       | OP                                         | OP                                        |
| Aktywna                 | Tak                     | Całkowity        | Kontrolowana        | OP                                       | ND                                         | ND                                        |
| Aktywna                 | Tak                     | Całkowity        | Otwarta             | ND                                       | ND                                         | ND                                        |
