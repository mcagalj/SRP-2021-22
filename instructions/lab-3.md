<!--omit-->
# **Sigurnost računala i podataka (Lab 3)** <!-- omit in toc -->

- [Message authentication and integrity](#message-authentication-and-integrity)
  - [Message Authentication Code (MAC)](#message-authentication-code-mac)
    - [Izazov 1](#izazov-1)
    - [Izazov 2](#izazov-2)
      - [Kako preuzeti sve izazove sa servera?](#kako-preuzeti-sve-izazove-sa-servera)
      - [Za provjeru MAC-a treba mi korištena tajna/ključ, gdje ću je naći?](#za-provjeru-mac-a-treba-mi-korištena-tajnaključ-gdje-ću-je-naći)
      - [Ali ne želim ponavljati manualno provjeru svih transakcija](#ali-ne-želim-ponavljati-manualno-provjeru-svih-transakcija)
      - [Ne želim otvarati manualno pojedinačne datoteke da bih pročitao _timestamp_-ove](#ne-želim-otvarati-manualno-pojedinačne-datoteke-da-bih-pročitao-timestamp-ove)
  - [Digital signatures using public-key cryptography](#digital-signatures-using-public-key-cryptography)
    - [Kako učitati javni ključ iz datoteke?](#kako-učitati-javni-ključ-iz-datoteke)
    - [Kako provjeriti ispravnost digitalnog potpisa?](#kako-provjeriti-ispravnost-digitalnog-potpisa)

# Message authentication and integrity

Cilj vježbe je primjeniti teoreteske spoznaje o osnovnim kritografskim mehanizmima za autentikaciju i zaštitu integriteta poruka u praktičnom primjerima. Pri tome ćemo koristiti simetrične i asimetrične krito mehanizme: _message authentication code (MAC)_ i _digitalne potpise_ zasnovane na javnim ključevima.

## Message Authentication Code (MAC)

### Izazov 1

Implementirajte zaštitu integriteta sadržaja dane poruke primjenom odgovarajućeg _message authentication code (MAC)_ algoritma. Koristite pri tome HMAC mehanizam iz Python biblioteka [`cryptography`](https://cryptography.io/en/latest/hazmat/primitives/mac/hmac/).

1. U lokalnom direktoriju kreirajte tekstualnu datoteku odgovarajućeg sadržaja čiji integritet želite zaštititi.

2. Učitavanje sadržaja datoteke u memoriju.

   ```python
    # Reading from a file
    with open(filename, "rb") as file:
        content = file.read()   
   ```

3. Funkcija za izračun MAC vrijednosti za danu poruku.

    ```python
    from cryptography.hazmat.primitives import hashes, hmac

    def generate_MAC(key, message):
        if not isinstance(message, bytes):
            message = message.encode()

        h = hmac.HMAC(key, hashes.SHA256())
        h.update(message)
        signature = h.finalize()
        return signature
    ```

4. Funkcija za provjeru validnosti MAC-a za danu poruku.

    ```python
    from cryptography.hazmat.primitives import hashes, hmac
    from cryptography.exceptions import InvalidSignature
    

    def verify_MAC(key, signature, message):
        if not isinstance(message, bytes):
            message = message.encode()
    
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(message)
        try:
            h.verify(signature)
        except InvalidSignature:
            return False
        else:
            return True
    ```

5. Pokušajte modificirati sadržaj datoteke i/ili potpis (odnosno MAC vrijednost) i uvjerite se da MAC algoritam uspješno detektira takve promjene.

### Izazov 2

U ovom izazovu **želite utvrditi vremenski ispravnu skevencu transakcija (ispravan redosljed transakcija) sa odgovarajućim dionicama**. Digitalno potpisani (primjenom MAC-a) nalozi za pojedine transakcije nalaze se na lokalnom web poslužitelju:

[http://a507-server.local](http://a507-server.local)

**NAPOMENA:** Da bi pristupili serveru **trebate** biti dio lokalne mreže. Ako ni u tom slučaju niste u mogućnosti povezati se na server moguće je da server nije pokrenut, pa upozorite profesora.

Sa servera preuzmite personalizirane izazove (direktorij `prezime_ime/mac_challege`). Nalozi se nalaze u datotekama označenim kao `order_<n>.txt` a odgovarajući autentikacijski kod (_digitalni potpis_) u datotekama `order_<n>.sig`.

#### Kako preuzeti sve izazove sa servera?

1. Preuzmite program `wget` dostupan na [wget download](https://eternallybored.org/misc/wget/).

2. Pohranite ga u direktorij gdje ćete pisati Python skriptu rješavanje ovog izazova.

3. Osobne izazove preuzimate izvršavanjem sljedeće naredbe u terminalu:

   ```console
   wget.exe -r -nH -np --reject "index.html*" http://a507-server.local/challenges/prezime_ime/
   ```

#### Za provjeru MAC-a treba mi korištena tajna/ključ, gdje ću je naći?

Tajna vrijednost koja se koristi kao ključ u MAC algoritmu dobivena je iz vašeg imena (ne pretjerano siguran pristup):

```python
key = "cagalj_mario".encode()
```

#### Ali ne želim ponavljati manualno provjeru svih transakcija

_Fair enough_, koristite nekakvu petlju: 

```python

for ctr in range(1:11):
    msg_filename = f"order_{ctr}.txt"
    sig_filename = f"order_{ctr}.sig"    
    print(msg_filename)
    print(sig_filename)
```

#### Ne želim otvarati manualno pojedinačne datoteke da bih pročitao _timestamp_-ove

```python
for ctr in range(1:11):
    msg_filename = f"order_{ctr}.txt"
    sig_filename = f"order_{ctr}.sig"    
    print(msg_filename)
    print(sig_filename)

    is_authentic = ...

    print(f'Message {message:>45} {"OK" if is_authentic else "NOK":<6}')
```

## Digital signatures using public-key cryptography

U ovom izazovu trebate odrediti autentičnu sliku (između dvije ponuđene) koju je profesor potpisao svojim privatnim ključem. Odgovarajući javni ključ dostupan je na gore navedenom serveru.

Slike i odgovarajući digitalni potpisi nalaze se u direktoriju `prezime_ime\public_key_challenge`. Kao i u prethodnoj vježbi, za rješavanje ove koristite Python biblioteku [`cryptography`](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/) - konkretnije **RSA kriptosustav**.


### Kako učitati javni ključ iz datoteke?

I kako ga _deserijalzirati_ (što god to značilo).

```python
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def load_public_key():
    with open(PUBLIC_KEY_FILE, "rb") as f:
        PUBLIC_KEY = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    return PUBLIC_KEY
```

### Kako provjeriti ispravnost digitalnog potpisa?

```python
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature


def verify_signature_rsa(signature, message):
    PUBLIC_KEY = load_public_key()
    try:
        PUBLIC_KEY.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except InvalidSignature:
        return False
    else:
        return True
```
