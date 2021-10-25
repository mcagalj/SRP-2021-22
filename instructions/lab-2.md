# **Sigurnost računala i podataka (Lab 2)**

## Symmetric key cryptography - a crypto challenge

U sklopu vježbe student će riješiti odgovarajući _crypto_ izazov, odnosno dešifrirati odgovarajući _ciphertext_ u kontekstu simetrične kriptografije. Izazov počiva na činjenici da student nema pristup enkripcijskom ključu.

## Uvod

Za pripremu _crypto_ izazova, odnosno enkripciju korištena je Python biblioteka [`cryptography`](https://cryptography.io/en/latest/). _Plaintext_ koji student treba otkriti enkriptiran je korištenjem _high-level_ sustava za simetričnu enkripciju iz navedene biblioteke - [Fernet](https://cryptography.io/en/latest/fernet/).

### [Fernet](https://github.com/fernet/spec/blob/master/Spec.md)

Fernet koristi sljedeće _low-level_ kriptografske mehanizme: 

* AES šifru sa 128 bitnim ključem 
* CBC enkripcijski način rada 
* HMAC sa 256 bitnim ključem za zaštitu integriteta poruka
* Timestamp za osiguravanje svježine (_freshness_) poruka

U ovom dijelu vježbi, najprije ćemo se kratko upoznati sa načinom na koji možete enkriptirati i dekriptirati poruke korištenjem Fernet sustava.

> NAPOMENA: Preduvjet za rad na vježbi je instaliran [Python](https://www.python.org/) (verzija 3).

### Crypto challenge

U nastavku su informacije relevantne za uspješno rješavanje _crypto_ izazova.

1. Vaš izazov je rezultat enkripcije odgovarajućeg personaliziranog _plaintext_-a korištenjem Fernet sustava.

2. Personalizirani izazovi dostupni su putem internog servera (koristite web preglednik za pristup) na sljedećoj adresi 

    [http://a507-server.local](http://a507-server.local)

    **NAPOMENA:** Da bi pristupili serveru **trebate** biti dio lokalne mreže. Ako ni u tom slučaju niste u mogućnosti povezati se na server moguće je da server nije pokrenut, pa upozorite profesora.

3. Preuzmite osobni izazov sa severa na lokalno računalo. Izazov je pohranjen u datoteku čiji naziv generiramo na sljedeći format:

    ```python
    from cryptography.hazmat.primitives import hashes

    def hash(input):
        if not isinstance(input, bytes):
            input = input.encode()

        digest = hashes.Hash(hashes.SHA256())
        digest.update(input)
        hash = digest.finalize()

        return hash.hex()

    filename = hash('prezime_ime') + ".encrypted"
    ```

4. Za enkripciju smo koristili **ključeve ograničene entropije - 22 bita**. Ključevi su generirani na sljedeći način:

   ```python
    # Encryption keys are 256 bits long and have the following format:
    #           
    #              0...000b[1]b[2]...b[22] 
    #
    # where b[i] is a randomly generated bit.
    key = int.from_bytes(os.urandom(32), "big") & int('1'*KEY_ENTROPY, 2)
    
    # Initialize Fernet with the given encryption key;
    # Fernet expects base64 urlsafe encoded key.
    key_base64 = base64.urlsafe_b64encode(key.to_bytes(32, "big"))
    fernet = Fernet(key_base64) 
   ```

5. Konačno u opisanom sustavu enkriptiramo vaš izazov i pohranimo ga na gore opisan način.

Vaš zadatak je dešifrirati osobni _crypto_ izazov i pohraniti ga u odgovarajuću datoteku. Pri tome trebate uvjeriti sebe i druge da ste uistinu uspješno dekritpirali vaš izazov.

U nastavku dajemo neke smjernice i isječke koda koje vam mogu biti od pomoći pri rješavanju izazova. Razmislite i skicirajte pristup rješavanju problema prije nego započmente s pisanjem koda.

#### Učitavanje i spremanje datoteka u Pythonu

```python
# Reading from a file
with open(filename, "rb") as file:
    ciphertext = file.read()
    # Now do something with the ciphertext
```

```python
# Writing to a file
with open(filename, "wb") as file:
    file.write("Hello world!")
```

#### Iteriranje kroz ključeve (_enumerating all possible keys_)

```python
ctr = 0
while True:
    key_bytes = ctr.to_bytes(32, "big")
    key = base64.urlsafe_b64encode(key_bytes)

    # Now initialize the Fernet system with the given key
    # and try to decrypt your challenge.
    # Think, how do you know that the key tested is the correct key
    # (i.e., how do you break out of this infinite loop)?

    ctr += 1
```

#### Što sa entropijom od 22 bita?

Moguće je da pri rješavanju izazova shvatite da 22 bita entropije i nije tako mali izazov za rješiti u okviru labova i na raspoloživom hardveru. Ako želite biti malo efikasniji možete pokušati bolje iskoristiti postojeće resurs (sve procesorske jezgre - _paralelizacija_). Python [multiprocessing](https://docs.python.org/3/library/multiprocessing.html) paket može biti od velike pomoći.

```python
from multiprocessing import Pool

def brute_force(filename, chunk_start_index, chunk_size):
    ctr = 0

    while True:
        # Here you test your candidate keys


def parallelize_attack(filename, key_entropy):
    # Split the keyspace into equally sized chunks;
    # the number of chunks corresponds to the number 
    # of CPU cores on your system.
    total_keys = 2**key_entropy
    chunk_size = int(total_keys/os.cpu_count())

    with Pool() as pool:
        def key_found_event(event):
            print("Terminating the pool ...")
            pool.terminate()

        # Start parallel workers
        for chunk_start_index in range(0, total_keys, chunk_size):
            pool.apply_async(
                brute_force,
                (
                    filename,
                    chunk_start_index,
                    chunk_size,
                ),
                callback=key_found_event
            )

        pool.close()
        pool.join()
```

> **NAPOMENA:** Ne zaboravite pripremiti kratak izvještaj i postaviti ga u svoj repozitorij.