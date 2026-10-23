import time
from .common import device_context_from_params, parse_url_params, url_query
from .x_argus import Argus
from .x_cylons import Cylons
from .x_gorgon import get_xgorgon
from .x_helios import Helios
from .x_ladon import Ladon
from .x_medusa import Medusa
from .x_perseus import Perseus


class DouyinSigner:
    def __init__(self):
        self._argus = Argus()
        self._cylons = Cylons()
        self._ladon = Ladon()
        self._helios = Helios()
        self._medusa = Medusa()
        self._perseus = Perseus()

    def sign(
        self,
        url: str,
        body="",
        cookie: str = "",
        stub: str = "",
        content_type: str = "application/x-www-form-urlencoded; charset=UTF-8",
        timestamp=None,
    ) -> dict:
        params = parse_url_params(url)
        aid = params.get("aid", "1128")
        device_id = params.get("device_id", "")
        version_name = params.get("version_name", "")
        license_id = "1588093228"
        devices = device_context_from_params(params)

        ts = int(timestamp) if timestamp not in (None, "") else int(time.time())
        x_gorgon = get_xgorgon(ts, url, str(body), cookie)
        timestamp = str(ts)
        query = url_query(url)

        return {
            "x-gorgon": x_gorgon,
            "x-khronos": timestamp,
            "x-ss-req-ticket": str(ts * 1000),
            "x-argus": self._argus.get_value(timestamp, aid=aid, device_id=device_id, version_name=version_name, stub=stub, query=query),
            "x-cylons": self._cylons.get_value(timestamp=timestamp, device_id=device_id),
            "x-ladon": self._ladon.get_value(timestamp, aid=aid),
            "x-helios": self._helios.get_value(timestamp, aid=aid, license_id=license_id),
            "x-medusa": self._medusa.get_value(
                timestamp,
                url=url,
                params=params,
                devices=devices,
                body=body,
                content_type=content_type,
                aid=aid,
                license_id=license_id,
            ),
            "x-perseus": self._perseus.get_value(
                timestamp,
                url=url,
                body=body,
                device_id=device_id,
                version_name=version_name or "39.3.0",
            ),
        }
