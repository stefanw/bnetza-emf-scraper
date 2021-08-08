# BNetzA EMF Datenbank Scraper


Install requirements:

```
python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
```

Test scraper on position:

```
# python emf_scraper.py <lng,lat>
# e.g.
python emf_scraper.py 10.249166,47.350833
```

Run scraper:

```
python emf_scraper.py
```

This creates a `data/` directory and writes results in there.

## Credits

Based on https://github.com/KoelnAPI/data/tree/master/data/communication/bundesnetzagentur-emf
