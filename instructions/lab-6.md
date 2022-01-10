# Lab 6 - Linux permissions and ACLs

U okviru vježe student će se upoznati s osnovnim postupkom upravljanja korisničkim računima na Linux OS-u. Pri tome će se poseban naglasak staviti na **kontrolu pristupa (eng. *access control*)** datotekama, programima i drugim resursima Linux sustava.

Za listu i opis Linux naredbi korisnih za realizaciju zadataka u nastavku konzultirajte izvrstan dokument *[Linux Security](http://linux-training.be/linuxsec.pdf)*.

## A. Kreiranje novog korisničkog računa

U Linux-u svaka datoteka ili program (*binary executable file*) ima vlasnika (*user or owner*). Svakom korisniku pridjeljen je jedinstveni identifikator *User ID (UID)*. Svaki korisnik mora pripadati barem jednoj grupi (*group*), pri čemu više korisnika može dijeliti istu grupu. Linux grupe također imaju jedinstvene identifikatore *Group ID (GID)*.

1. Identifikatore `uid`, `gid` i pripadnost grupama možete provjeriti kako je prikazano u nastavku (ovu naredbu izvršite u *shell-u* u WSL na vašem lokalnom računalu):
    
    ```bash
    id
    ```
    
    Uvjerite se da pripadate administratorskoj grupi `sudo`; za ispis samo grupa kojima pripadate možete koristiti naredbu `groups`.
    
2. Kreirajte novi korisnički račun (npr. `alice`). Pri tome možete koristiti naredbu `adduser` (odnosno `deluser` za brisanje postojećeg korisničkog računa). Logirajte se kao novi korisnik i saznajte vaš `uid`, `guid` i sve dodatne grupe kojim pripadate.
    
    **NAPOMENA:** Ovo možete izvrštiti samo ako imate administratorske ovlasti (odnosno pripadate grupi `sudo`).
    
    ```bash
    sudo adduser alice
    ```
    
3. Logirajte se kao novi korisnik i saznajte odgovarajuće identifikatore korisnika i grupa kojima korisnik pripada.
    
    ```bash
    su - alice
    ```
    
4. Kreirajte još jedan korisnički račun (npr. `bob`). 
    
    NAPOMENA: Ne zaboravite da za ovo trebate administratorske ovlasti. Izvršavanjem naredbe `exit` u *shell*-u prethodnog korisnika `alice` vraćate se u `shell` korisnika koji ima administratorske ovlasti (odnosno član je grupe `sudo`).
    

## **B. Standardna prava pristupa datotekama**

1. Logirajte se u sustav kao novi korisnik (npr. `alice`). U korisnikovom *home* direktoriju (`/home/alice`) kreirajte novi direktorij `srp` te u njemu datoteku `security.txt` (upišite proizvoljan tekst).
    
    ```bash
    # navigate to home directory
    cd
    
    # create a new directory
    mkdir
    
    # create a file with text
    echo "Hello world" > security.txt
    
    # print file content
    cat security.txt
    ```
    
2. Izlistajte informacije o novom direktoriju i datoteci. Odredite vlasnike ovih resursa (korisnike i grupe) kao i dopuštenja (*access permissions*) definirana na njima. Pri tome možete koristiti neku od sljedećih naredbi: `ls -l` ili `getfacl`.
    
    ```bash
    ls -l .
    ls -l srp
    ls -l srp/security.txt
    
    getfacl srp
    getfacl srp/security.txt
    getfacl -t srp/security.txt
    ```
    
3. Oduzmite pravo pristupa datoteci `security.txt` vlasniku datoteke modifikacijom dopuštenja (*access permissions*). Za promjenu dopuštenja koristite naredbu `chmod`. Testirajte ispravnost vaših rješenja.
    
    **NAPOMENA:** U dokumentu [*Linux Security*](http://linux-training.be/linuxsec.pdf) možete naći primjere primjene chmod naredbe.
    
    U nastavku su dani neki primjeri primjene `chmod` naredbe:
    
    ```bash
    # Remove (u)ser (r)ead permission
    chmod u-r security.txt
    
    # Add (u)ser (r)ead permission
    chmod u+r security.txt
    
    # Remove both (u)ser and (g)roup (w)rite permission
    chmod ug-w security.txt
    
    # Add (u)ser (w)rite and remove (g)roup (r)ead permission
    chmod u+w,g-r security.txt
    
    # Add (u)ser (r)read, (w)rite permissions and remove e(x)ecute permpission
    chmod u=rw security.txt 
    ```
    
4. Oduzmite pravo pristupa datoteci `security.txt` vlasniku datoteke na način da mu u tom postupku **ne odzimate `(r)ead` dopuštenje nad datotekom**. 
    
    **NAPOMENA:** Ovo možete realizirati modifikacijom dopuštenja na *parent* direktoriju (`srp`). Oduzimanjem `(r)ead` prava na direktoriju oduzimate pravo ispisivanja/listanja (`ls`) njegovog sadržaja, dok oduzimanjem `e(x)ecute` prava oduzimate pravo ulaska (`cd`) u direktorij.
    
5. U dopunskom terminalu logirajte se kao drugi korisnik (npr. `bob`) i pokušajte pročitati sadržaj datoteke `security.txt` (koja pripada drugom korisnku, npr. `alice`). Oduzmite prava pristupa novom korisniku (`bob`) sadržaju ove datoteke.
6. Sada ponovo omogućite novom korisniku (`bob`) pristup sadržaju datoteke `security.txt` ali na način da taj korisnik ima pristup datoteci isključivo ako je član grupe koja je vlasnik predmetne datoteke `security.txt`.
    
    ```bash
    # 1. Learn the group that owns the filw using getfacl command
    # 2. Add new user (bob) to that group (requires administrator privileges)
    usermod -aG <owner_group> bob
    
    # 3. Logout and login for this change to take effect
    # 4. Verify the group membership of bob
    id
    # 5. Finally, try to read the file content
    ```
    
7. Logirajte se kao jedan dodanih korisnika i pokušajte pročitati sadržaj datoteke `/etc/shadow` u koju Linux pohranjuje *hash* vrijednosti korisničkih zaporki. Što ste uočili prilikom pokušaja pristupa navedenim datotekama? Objasnite razlog tog ishoda; odredite vlasnike navedenih datoteka (korisnike i grupe) kao i dopuštenja definirana na njima.
    
    Koristeći saznanja iz prethodnih koraka omogućite korisniku pristup sadržaju datoteke `/etc/shadow`.
    
8. Uklonite novog korisnika iz grupa `alice` i `shadow` (potrebne su administratorske ovlasti). 
    
    ```bash
    # gpasswd -d <user> <group>
    gpasswd -d bob alice
    gpasswd -d bob shadow
    ```
    

## C. Kontrola pristupa korištenjem *Access Control Lists (ACL)*

Za inspekciju i modifikaciju ACL-ova resursa (datoteka, direktorija) koristimo programe `getfacl` i `setfacl`.

1. Uvjerite se da novi korisnik `bob` nema pristup sadržaju datoteke `security.txt` korisnika `alice`.
2. U prethodnom zadatku pristup sadržaju smo omogućili dodavanjem novog korisnika u grupu koja je vlasnik predmetne datoteke. Korištenjem ACL, ovo možemo jednostavnije rješiti tako da u ACL datoteke `security.txt` dodamo novog korisnika sa `(r)ead` ovlastima (potrebne su administratorske ovlasti).
    
    ```bash
    # 1. Read/record current permissions defined on the file
    getfacl security.txt
    
    # 2. Add (u)ser bob to the ACL list of the file with (r)ead premission
    setfacl -m u:bob:r security.txt
    
    # 3. Check the updated permissions defined on the file
    getfacl security.txt
    
    # 4. Login as bob, navigate to the file and try to read its content
    cat security.txt
    ```
    
3. Uklanjanje zapisa iz ACL-a.
    
    ```bash
    # Removing one entry from ACL
    setfacl -x u:bob security.txt
    
    # Removing the complete ACL
    setfacl -b security.txt
    ```
    
4. Pokušajte omogućiti novom korisniku pristup sadržaju datoteke `security.txt` ali kroz članstvo u grupi (novu grupu možete prigodno nazvati `alice_reading_group`).
    
    Novu grupu možete kreirati kako slijedi (zahtjeva administratorske ovlasti):
    
    ```bash
    groupadd alice_reading_group
    ```
    
5. **OPCIONALAN ZADATAK**
    
    Koristeći Linux ACL pokušajte implementirati politiku pristupa definiranu sljedećom matricom pristupa (*access matrix*).
    
    |       | file_alice_1     | file_alice_2     | file_bob  | file_carol  |
    | ----- | ---------------- | ---------------- | --------- | ----------- |
    | alice | own, read, write | own, read, write | write     |             |
    | bob   | write            | write            | own, read | read, write |
    | carol | read, write      |                  | read      | own, read   |

## D. Linux procesi i kontrola pristupa

Linux procesi su programi koji se trenutno izvršavaju u odgovarajućem adresnom prostoru. Trenutno aktivne procese možete izlistati korištnjem naredbe `ps -ef`. Primjetite da proces ima vlasnika (`UID`) i jedinstveni identifikator procesa, *process identifier* `PID`.

1. Uvjerite se da novi korisnik `bob` nema pristup sadržaju datoteke `security.txt`. U prethodnom zadatku to smo omogućili putem ACL i dodavanjem korisnika `bob` u grupu `alice_reading_group`. Uklonite korinika `bob` iz grupe kako slijedi:
    
    ```bash
    gpasswd -d bob alice_reading_group
    ```
    
2. Otvorite *WSL shell* i u tekućem direktoriju kreirajte Python skriptu sljedećeg sadržaja.
    
    ```python
    import os
    
    print('Real (R), effective (E) and saved (S) UIDs:') 
    print(os.getresuid())
    
    with open('/home/alice/srp/security.txt', 'r') as f:
        print(f.read())
    ```
    
3. Izvršite skriptu i komentirajte rezultat.
4. Prijavite se kao korisnik `bob` i pokrenite istu skriptu. Komentirajte rezultat.
5. Prijavite se kao korisnik `alice` i pokrenite istu skriptu. Što uočavate? Izvedite zaključak. 
6. **OPCIONALAN ZADATAK**
    
    U kontekstu onog što smo naučili iz prethodnih zadataka o načinu na koji Linux regulira pristup resursima, razmislite o sljedećem scenariju. Logirate se u sustav kao neprivilegirani korisnik (npr. `alice`) i želite promjeniti zaporku. Zaporku možete promjeniti korištenjem naredbe `passwd`. Sustav će vam dopustiti promjenu zaporke i ažurirat će datoteku `/etc/shadow` sa novom *hash* vrijednosti vaše zaporke. **Ako nemate prava pristupa datoteci `/etc/shadow` (vlasnik je korisnik sa `uid = 0`) a pokretanjem programa `passwd` ovaj program preuzima vaš `uid`, kako je moguće da možete napraviti promjenu u navedenoj datoteci i time ažurirati vašu zaporku?**
    
    Jedan od mehanizama koji Linux koristi u ovakvim slučajevima je mehanizam *efektivnog vlasnika procesa*. Naime, svakom procesu je uz stvarnog vlasnika (označenog sa *real user id - `RUID`*) pridjeljen i *efektivni vlasnik* (*`EUID`*) koji kernel koristi pri provjeri pristupa tog procesa nekom resursu. U većini slučajeva (`RUID = EUID`) osim kad je program označen sa specijalnim `setuid` bitom (vidi primjer u nastavku).
    
    ```bash
    # Note that in place of "x" flag, we now have "s" flag
    ls -l $(which passwd)
    -rwsr-xr-x 1 root root 59640 Mar 22  2019 /usr/bin/passwd
    
    getfacl $(which passwd)
    # file: usr/bin/passwd
    # owner: root
    # group: root
    # flags: s--
    user::rwx
    group::r-x
    other::r-x
    ```
    
    Opisani mehanizam možemo demonstrirati na sljedeći način.
    
    1. Izvršite naredbu `passwd` (kao neprivilagirani korisnik).
        
        ```bash
        passwd
        Changing password for alice.
        (current) UNIX password:
        # !!! NEMOJTE UNOSITI NIKAKVU LOZINKU !!!
        ```
        
    2. U drugom terminalu izvršite sljedeću naredbu (koja će vam ispisati tekuće procese sa njihovim stvarnim i efektivnim vlasnicima):
        
        ```bash
        ps -eo pid,ruid,euid,suid,cmd
        ```
        
        Pronađite u ispisu liniju koja odgovara programu `passwd` i prokomentirajte `RUID`, `EUID` i `SUID` polja.