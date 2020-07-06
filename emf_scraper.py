import base64
import json
import logging
import os
import re
import sys

from lxml import html

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import requests

logger = logging.getLogger()


# Bounding box for data scraping: Germany
# order: west, south, east, north
BBOX = (5.98865807458, 47.3024876979, 15.0169958839, 54.983104153)

# step with in degrees for partial worj through bounding box
# (0.05 seems to work fine)
STEP = 0.05


def unpad(s):
    return s[0:-int(s[-1])]


def to_float(s):
    if s is None:
        return s
    s = s.strip().replace(',', '.')
    try:
        return float(s)
    except ValueError:
        return s


class EMFScraper():
    proxies = None
    headers = {
        'Origin': 'https://www.bundesnetzagentur.de',
        'Accept-Language': 'de;q=0.8',
        'X-Prototype-Version': '1.7.1',
        'X-Requested-With': 'XMLHttpRequest',
        'dataType': 'json',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.75 Safari/537.36',
        'Content-type': 'application/json; charset=UTF-8 application/json',
        'Accept': 'application/json',
        'Referer': 'https://www.bundesnetzagentur.de/emf-karte/'
    }
    CRYPTO_PW_RE = re.compile(r'var c=CryptoJS\.enc\.Utf8\.parse\("(.*?)"\);')

    def __init__(self):
        self.kinds = {
            'GetStandorteFreigabe': self.get_standort_details,
            'GetMessorte': self.get_default_details,
            'GetAMSAktiv': self.get_default_details,
            'GetAFuFreigabe': self.get_default_details,
        }

    def init_session(self):
        """
        Get valid session ID and store to cookie jar
        """
        url = "https://www.bundesnetzagentur.de/emf-karte/"
        self.session = requests.Session()
        response = self.session.get(url, proxies=self.proxies)
        js_url = 'https://www.bundesnetzagentur.de/emf-karte/js.asmx/jscontent?set=emf'
        response = self.session.get(js_url, proxies=self.proxies)
        match = self.CRYPTO_PW_RE.search(response.text)
        self.password = match.group(1)

    def get_positions(self, bbox, kind):
        """
        Get antenna positions for a bounding box,
        """
        west, south, east, north = bbox

        data = {
            "Box": {
                "nord": north,
                "ost": east,
                "sued": south,
                "west": west
            }
        }

        url = 'https://www.bundesnetzagentur.de/emf-karte/Standortservice.asmx/%s' % kind

        response = self.session.post(
            url,
            headers=self.headers,
            data=json.dumps(data),
            proxies=self.proxies
        )

        result = response.json()['d']

        if isinstance(result, dict) and result.get('SecMode'):
            result = self.decrypt(result['Result'])

        return result

    def decrypt(self, data):
        """
        // Convert JS decryption to Python
        var a = CryptoJS.enc.Hex.parse("a5a8d2e9c1721ae0e84ad660c472b1f3");
        var c = CryptoJS.enc.Utf8.parse("}EjJFyqYvj#?");
        var d = CryptoJS.enc.Utf8.parse("cryptography123example");
        var b = CryptoJS.PBKDF2(c.toString(CryptoJS.enc.Utf8), d, {
            keySize: 128 / 32,
            iterations: 1000
        });
        var e = {
            iv: a,
            Pass: c,
            Salt: d,
            key128Bits1000Iterations: b
        };
        var a = CryptoJS.lib.CipherParams.create({
            ciphertext: CryptoJS.enc.Base64.parse(e)
        });
        var c = CryptoJS.AES.decrypt(a, b.key128Bits1000Iterations, {
            mode: CryptoJS.mode.CBC,
            iv: b.iv,
            padding: CryptoJS.pad.Pkcs7
        });
        """
        backend = default_backend()

        iv = bytes.fromhex('a5a8d2e9c1721ae0e84ad660c472b1f3')
        pw = self.password.encode('utf-8')
        salt = 'cryptography123example'.encode('utf-8')
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA1(),
            length=int(128 / 8),
            salt=salt,
            iterations=1000,
            backend=backend
        )
        key = kdf.derive(pw)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)

        data_bytes = base64.b64decode(data)

        decryptor = cipher.decryptor()
        decrypted = decryptor.update(data_bytes) + decryptor.finalize()

        return json.loads(unpad(decrypted).decode('utf-8'))

    def get_default_details(self, fid, kind):
        return {
            'fid': fid,
            'kind': kind
        }

    def get_standort_details(self, fid, kind):
        """
        Fetch details on a certain antenna position
        """
        url = "https://www.bundesnetzagentur.de/bnetzachart/Standort.vtl.aspx"
        params = {
            "fid": fid
        }
        r = self.session.get(
            url, params=params,
            headers=self.headers
        )
        out = {
            "fid": fid,
            'kind': kind,
            "standortbescheinigung_nr": None,
            'datum': None,
            "antennas": []
        }
        root = html.fromstring(r.text)
        bnr = root.findall(".//div[@id='standortbnr']")
        if not bnr:
            return
        bnr_value = bnr[0].findall("span")[1]
        out["standortbescheinigung_nr"] = bnr_value.text_content()

        datum = root.xpath(".//div[@id='datum']/span[2]")
        if datum:
            out['datum'] = datum[0].text_content()

        tables = root.findall(".//table[@id='antennenTable']/tbody")
        if not tables:
            return out

        for row in tables[0].findall("tr"):
            atype, height, direction, hdistance, vdistance = row.findall("td")
            if direction.text_content().strip() == "ND":
                direction = None
            else:
                direction = to_float(direction.text_content())
            if hdistance.text_content().strip() == "nicht angegeben":
                hdistance = None
            else:
                hdistance = to_float(hdistance.text_content())
            if vdistance.text_content().strip() == "nicht angegeben":
                vdistance = None
            else:
                vdistance = to_float(vdistance.text_content())
            out["antennas"].append({
                "height": to_float(height.text_content()),
                "direction": direction,
                "type": atype.text_content().strip(),
                "hdistance": hdistance,
                "vdistance": vdistance
            })
        return out

    def get_bbox(self):
        south = BBOX[1]
        while south <= BBOX[3]:
            north = south + STEP
            west = BBOX[0]
            while west <= BBOX[2]:
                east = west + STEP
                yield (west, south, east, north)
                west += STEP
            south += STEP

    def load_bbox(self, bbox):
        for kind in self.kinds:
            for position in self.get_positions(bbox, kind):
                method = self.kinds[kind]
                details = method(position['fID'], kind)
                if details is not None:
                    details['position'] = position
                    yield details

    def run(self):
        try:
            with open('data/bbox.json') as f:
                already = set(json.load(f))
        except IOError:
            already = set()

        self.init_session()

        try:
            with open('data/positions.jsonl', 'a') as f:
                for bbox in self.get_bbox():
                    bbox_key = '|'.join(str(x) for x in bbox)
                    if bbox_key in already:
                        continue
                    logger.info('Current bbox: %s', bbox)
                    detail_count = 0
                    for detail in self.load_bbox(bbox):
                        f.write(json.dumps(detail))
                        f.write('\n')
                        detail_count += 1
                    if detail_count:
                        logger.info('Number of details %s', detail_count)
                    already.add(bbox_key)
            return True
        finally:
            with open('data/bbox.json', 'w') as f:
                json.dump(list(already), f)


def main():
    logging.basicConfig(stream=sys.stdout, level=logging.INFO)
    os.makedirs('data/', exist_ok=True)
    result = None
    while result is None:
        try:
            scraper = EMFScraper()
            result = scraper.run()
        except Exception as e:
            logger.exception(e)


if __name__ == "__main__":
    main()
