# -*- encoding: utf-8 -*-
"""header.py — URL解析与X-SS-STUB计算 (从dy34安卓v34迁移)"""
import hashlib
import json
import time
from urllib.parse import urlencode, unquote


def extract_url_params(url) -> dict:
    """从URL提取query参数为dict"""
    params = {}
    parsed_url_list = url.split("?")[1].split("&") if "?" in url else url.split("&")
    for param in parsed_url_list:
        splited_param = param.split("=")
        params[splited_param[0]] = unquote(splited_param[1] if len(splited_param) == 2 else "")
    return params


def url_encode(data):
    """URL编码,保持+和*的兼容处理"""
    param = urlencode(data)
    param = param.replace("+", "%20")
    param = param.replace("%2A", "*")
    return param


def get_params_encrypturl(url, params: dict = None, devices={}, common=None):
    """构造签名用URL和参数dict"""
    x_common = {}
    if params:
        x_params = params.copy()
        if common:
            x_params.update(extract_url_params(common))
            x_common = extract_url_params(common)
        if devices:
            for k, v in devices.items():
                if k in x_params:
                    x_params[k] = v
                if k in x_common:
                    x_common[k] = v
                elif "did" in x_params and k == "device_id":
                    x_params["did"] = v
    else:
        x_params = extract_url_params(url) if ("?" in url and len(url.split("?")) == 2 and url.split("?")[1]) else params
        if common:
            x_common = extract_url_params(common)
            x_params.update(x_common)
        if devices:
            for k, v in devices.items():
                if k in x_params:
                    x_params[k] = v
                if k in x_common:
                    x_common[k] = v
                elif "did" in x_params and k == "device_id":
                    x_params["did"] = v

    x_params["ts"] = int(time.time())
    x_params["_rticket"] = int(time.time() * 1e3)
    if x_common:
        x_common["ts"] = int(time.time())
        x_common["_rticket"] = int(time.time() * 1e3)
    eurl = url.split("?")[0] + "?" + url_encode(x_params) if "?" in url else url + "?" + url_encode(x_params)
    return eurl, x_params, url_encode(x_common)


def xssstub_hash_md5_hex(data, dataType: str = None):
    """计算X-SS-STUB (请求体MD5,大写hex)"""
    if not data:
        return str()
    if dataType == "md5":
        return data
    md5 = hashlib.md5()
    if isinstance(data, str):
        md5.update(data.encode('utf-8'))
    elif isinstance(data, bytes):
        md5.update(data)
    else:
        if dataType == "application/json; charset=UTF-8":
            md5.update(json.dumps(data, ensure_ascii=False, separators=(',', ':')).encode('utf-8'))
        else:
            md5.update(urlencode(data).encode('utf-8'))
    return md5.hexdigest().upper()
