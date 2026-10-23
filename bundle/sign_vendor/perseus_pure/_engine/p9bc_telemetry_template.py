"""Default telemetry template from device capture (PGZ110, event_num=1).

This template carries device-level constants and the f18/f19 hash fields
(which are request-varying on real device but cached here pending hash
input reverse engineering). The producer overwrites time-varying fields
from the request context; device-level fields are preserved.
"""
from __future__ import annotations

# 272-byte protobuf_chunk from submsg_serializer_leave event_num=1
# Captured on PGZ110 device, contains 22 fields (f1-f29)
PROTOBUF_TEMPLATE = bytes.fromhex(
    '0a106b9a2b2a429baf9181ca026ac236a4fe100e18f6ddd29305220431313238'
    '2a0f363932303137363034333735333935320a313537383039333232383a063339'
    '2e342e3042147630342e31302e30312d6d6c2d616e64726f6964488084d0405208'
    '000000000000000060f294d1a60d6a1414831abb4b2b12c9fcd000394de40792e7'
    '83390d7206d13d8080e56e7a10084c10bee15418bee154200e28bee15482011941'
    '4a504e4a7961704e524a67366341574a454a5550714a78758801f294d1a60d9201'
    '146961f16319a0bbcdcd7e1c89292714aebd08fa509a0120a02bcb29e42a5018eb'
    '5fb24719ec395526b2bc764d71e13b38b49699beba23d2a2010131a801e205e001'
    '9a0de801d596ede50e'
)

# JSON chunk template (device-level constants + placeholder time-varying fields)
# Based on captured json_chunk from _p9bd_chunks_extracted.json
# Note: ab_test.hit array and time-varying fields (fkd/pd/lp/fl) need caller input
JSON_TEMPLATE = (
    '{"ab_test":{"hit":["5665351","8068441","8886468","12306218","13627108",'
    '"13719264","14803483","15208455","15682318","1576"]},'
    '"build":"1128","device_id":"692017604375395","app_version":"v04.10.01",'
    '"timestamp":0,'
    '"cmr":16777216,"cmr2":16777216,"vpn":0,"sts":59,"tk":true,'
    '"un_h":0,"kd":0,"do":0,"fkd":0,"pd":0,'
    '"lp":"2|520830913191|0|0|0",'
    '"fl":"0|0|0|0|0|0|0|0|0|0"}'
).encode("utf-8")

__all__ = ["PROTOBUF_TEMPLATE", "JSON_TEMPLATE"]
