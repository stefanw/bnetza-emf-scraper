import base64
import json
import logging
import os
import re
import sys

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from lxml import html

logger = logging.getLogger()


# Bounding box for data scraping: Germany
# order: west, south, east, north
BBOX = (5.98865807458, 47.3024876979, 15.0169958839, 54.983104153)

# step with in degrees for partial work through bounding box
# (0.05 seems to work fine)
STEP = 0.05


def unpad(s):
    return s[0 : -int(s[-1])]


def to_float(s):
    if s is None:
        return s
    s = s.strip().replace(",", ".")
    try:
        return float(s)
    except ValueError:
        return s


class EMFScraper:
    proxies = None
    init_headers = {
        "Accept": "*/*",
        "Host": "www.bundesnetzagentur.de",
        "Origin": "https://www.bundesnetzagentur.de",
        "Accept-Language": "de;q=0.8",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36",
        "Referer": "https://www.bundesnetzagentur.de/DE/Vportal/TK/Funktechnik/EMF/start.html",
    }

    headers = {
        "Origin": "https://www.bundesnetzagentur.de",
        "Accept-Language": "de;q=0.8",
        "dataType": "json",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36",
        "Content-type": "application/json; charset=UTF-8 application/json",
        "Accept": "application/json",
        "Referer": "https://www.bundesnetzagentur.de/DE/Vportal/TK/Funktechnik/EMF/start.html",
    }
    CRYPTO_PW_RE = re.compile(r'var c=CryptoJS\.enc\.Utf8\.parse\("(.*?)"\);')

    def __init__(self):
        self.kinds = {
            "GetStandorteFreigabe": self.get_standort_details,
            "GetMessorte": self.get_messorte_details,
            "GetAMSAktiv": self.get_default_details,
            "GetAFuFreigabe": self.get_default_details,
            "GetStandorteFreigabeNF": self.get_default_details,
            "GetStandorteSmallCellFreigabe": self.get_default_details,
        }
        self.data_extras = {"GetStandorteFreigabeNF": {"zoomIgnore": False}}

    def init_session(self):
        """
        Get valid session ID and store to cookie jar
        """
        url = (
            "https://www.bundesnetzagentur.de/DE/Vportal/TK/Funktechnik/EMF/start.html"
        )
        self.session = requests.Session()
        response = self.session.get(
            url, headers=self.init_headers, proxies=self.proxies
        )
        js_url = (
            "https://www.bundesnetzagentur.de/emf-karte/js.asmx/jscontent?set=gsb2021"
        )
        response = self.session.get(
            js_url, headers=self.init_headers, proxies=self.proxies
        )
        match = self.CRYPTO_PW_RE.search(response.text)
        self.password = match.group(1)

    def get_positions(self, bbox, kind):
        """
        Get antenna positions for a bounding box,
        """
        west, south, east, north = bbox

        data = {"Box": {"nord": north, "ost": east, "sued": south, "west": west}}
        if kind in self.data_extras:
            data.update(self.data_extras[kind])

        url = (
            "https://www.bundesnetzagentur.de/emf-karte/Standortservice.asmx/%s" % kind
        )
        logger.info("request %s: %s ", kind, bbox)
        response = self.session.post(
            url, headers=self.headers, data=json.dumps(data), proxies=self.proxies
        )
        if "text/html" in response.headers["Content-Type"]:
            logger.info("request failed %s: %s ", kind, bbox)
            return None
        result = response.json()["d"]

        if isinstance(result, dict) and result.get("SecMode"):
            result = self.decrypt(result["Result"])

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

        iv = bytes.fromhex("a5a8d2e9c1721ae0e84ad660c472b1f3")
        pw = self.password.encode("utf-8")
        salt = "cryptography123example".encode("utf-8")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA1(),
            length=int(128 / 8),
            salt=salt,
            iterations=1000,
            backend=backend,
        )
        key = kdf.derive(pw)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)

        data_bytes = base64.b64decode(data)

        decryptor = cipher.decryptor()
        decrypted = decryptor.update(data_bytes) + decryptor.finalize()

        return json.loads(unpad(decrypted).decode("utf-8"))

    def get_default_details(self, fid, kind):
        return {"fid": fid, "kind": kind}

    def get_standort_details(self, fid, kind):
        """
        Fetch details on a certain antenna position
        """
        url = "https://www.bundesnetzagentur.de/emf-karte/hf.aspx"
        params = {"fid": fid}
        r = self.session.get(url, params=params, headers=self.headers)
        out = {
            "fid": fid,
            "kind": kind,
            "standortbescheinigung_nr": None,
            "datum": None,
            "antennas": [],
            "safety_distances": [],
            "methodSTOB": None,
        }
        root = html.fromstring(r.text)
        bnr = root.findall(".//div[@id='standortbnr']")
        if not bnr:
            return
        bnr_value = bnr[0].findall("span")[1]
        out["standortbescheinigung_nr"] = bnr_value.text_content()

        datum = root.xpath(".//div[@id='datum']/span[2]")
        if datum:
            out["datum"] = datum[0].text_content()

        tables = root.findall(".//div[@id='div_sendeantennen']/table")
        if tables:
            for row in tables[0].findall("tr")[1:]:
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
                out["antennas"].append(
                    {
                        "height": to_float(height.text_content()),
                        "direction": direction,
                        "type": atype.text_content().strip(),
                        "hdistance": hdistance,
                        "vdistance": vdistance,
                    }
                )
        tables = root.findall(".//div[@id='div_sicherheitsabstaende']/table")
        if tables:
            for row in tables[0].findall("tr")[1:]:
                label, hdistance, vdistance, height = row.findall("td")
                try:
                    hdistance = to_float(hdistance.text_content())
                except ValueError:
                    hdistance = None
                try:
                    vdistance = to_float(vdistance.text_content())
                except ValueError:
                    vdistance = None
                try:
                    height = to_float(height.text_content())
                except ValueError:
                    height = None
                out["safety_distances"].append(
                    {
                        "label": label.text_content().strip(),
                        "hdistance": hdistance,
                        "vdistance": vdistance,
                        "height": height,
                    }
                )

        # determine safety distances method
        if root.xpath(".//div[@id='standortWattwaechter']"):
            # - "_f_eldtheoretisch"
            out["methodSTOB"] = "f"
        elif root.xpath(".//div[@id='standortGrenzmessung']"):
            # - "_m_esstechnisch"
            out["methodSTOB"] = "m"
        else:
            # - "_r_echnerisch"
            out["methodSTOB"] = "r"

        return out

    def get_messorte_details(self, fid, kind):
        """
        Fetch details on a certain messort
        """
        url = "https://www.bundesnetzagentur.de/bnetzachart/Messort.vtl.aspx"
        params = {"fid": fid}
        r = self.session.get(url, params=params, headers=self.headers)
        out = {
            "fid": fid,
            "kind": kind,
            "bed12": None,
            "bed34": None,
        }

        res = re.findall(r"(\d+(?:.\d+)?) Prozent", r.text)
        if len(res) == 2:
            out["bed12"] = float(res[0].replace(",", "."))
            out["bed34"] = float(res[1].replace(",", "."))
            return out
        else:
            return None

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

    def make_bbox(self, lnglat):
        HSTEP = STEP / 2.0
        return (
            lnglat[0] - HSTEP,
            lnglat[1] - HSTEP,
            lnglat[0] + HSTEP,
            lnglat[1] + HSTEP,
        )

    def load_bbox(self, bbox):
        for kind in self.kinds:
            positions = self.get_positions(bbox, kind)
            if positions is None:
                return
            for position in positions:
                method = self.kinds[kind]
                details = method(position["fID"], kind)
                if details is not None:
                    details["position"] = position
                    yield details

    def run_position(self, lnglat):
        self.init_session()
        bbox = self.make_bbox(lnglat)
        for detail in self.load_bbox(bbox):
            sys.stdout.write(json.dumps(detail))
            sys.stdout.write("\n")

    def run(self):
        try:
            with open("data/bbox.json") as f:
                already = set(json.load(f))
        except IOError:
            already = set()

        self.init_session()

        bbox_count = sum(1 for _ in self.get_bbox())
        count = 0
        try:
            with open("data/positions.jsonl", "a") as f:
                for bbox in self.get_bbox():
                    count += 1
                    bbox_key = "|".join(str(x) for x in bbox)
                    if bbox_key in already:
                        continue
                    logger.info("Current bbox: %s", bbox)
                    logger.info("Progress: %s %%", round(count / bbox_count * 100, 1))
                    detail_count = 0
                    for detail in self.load_bbox(bbox):
                        f.write(json.dumps(detail))
                        f.write("\n")
                        detail_count += 1
                    if detail_count:
                        logger.info("Number of details %s", detail_count)
                    already.add(bbox_key)
            return True
        finally:
            with open("data/bbox.json", "w") as f:
                json.dump(list(already), f)


def main():
    if len(sys.argv) == 2:
        logging.basicConfig(stream=sys.stderr, level=logging.INFO)
        pos = sys.argv[1].split(",")
        lng, lat = float(pos[0]), float(pos[1])
        #  10.216111,47.348333
        scraper = EMFScraper()
        return scraper.run_position((lng, lat))

    logging.basicConfig(stream=sys.stdout, level=logging.INFO)
    os.makedirs("data/", exist_ok=True)
    result = None
    while result is None:
        try:
            scraper = EMFScraper()
            result = scraper.run()
        except Exception as e:
            logger.exception(e)


if __name__ == "__main__":
    main()
