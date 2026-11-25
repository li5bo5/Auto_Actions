# -*- coding: utf-8 -*-
"""天翼云盘自动签到脚本（PC 统一登录版）。"""

import os
import re
import sys
import time
import rsa
import requests

WEB_URL = "https://cloud.189.cn"
AUTH_URL = "https://open.e.189.cn"
API_URL = "https://api.cloud.189.cn"

APP_ID = "8025431004"
CLIENT_TYPE = "10020"
ACCOUNT_TYPE = "02"
RETURN_URL = "https://m.cloud.189.cn/zhuanti/2020/loginErrorPc/index.html"
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/87.0.4280.88 Safari/537.36"
)


def rsa_encrypt(pub_key: str, text: str) -> str:
    """使用服务端返回的 RSA 公钥加密文本并返回十六进制字符串。"""
    pem = f"-----BEGIN PUBLIC KEY-----\n{pub_key}\n-----END PUBLIC KEY-----"
    pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(pem.encode("utf-8"))
    return rsa.encrypt(text.encode("utf-8"), pubkey).hex()


def mask_account(account: str) -> str:
    """对账号进行脱敏处理，避免在公开日志中暴露完整手机号。"""
    if len(account) >= 7:
        return f"{account[:3]}****{account[-4:]}"
    if len(account) >= 3:
        return f"{account[0]}***{account[-1]}"
    return "****"


def _check_api_error(data: dict, action: str) -> None:
    """检查接口响应中的常见业务错误字段。"""
    error_code = data.get("errorCode") or data.get("res_code")
    if error_code and str(error_code) != "0":
        error_msg = data.get("errorMsg") or data.get("res_message") or data.get("msg") or "未知错误"
        raise RuntimeError(f"{action}失败：errorCode={error_code}, msg={error_msg}")


def get_encrypt_conf(session: requests.Session) -> tuple[str, str]:
    """获取登录公钥及密码前缀标识。"""
    resp = session.post(f"{AUTH_URL}/api/logbox/config/encryptConf.do", timeout=15)
    resp.raise_for_status()
    payload = resp.json()
    if str(payload.get("result")) != "0" or not isinstance(payload.get("data"), dict):
        raise RuntimeError(f"获取加密配置失败：result={payload.get('result')}, msg={payload.get('msg')}")
    data = payload["data"]
    pub_key = data.get("pubKey")
    pre = data.get("pre", "")
    if not pub_key:
        raise RuntimeError("获取加密配置失败：响应缺少 pubKey")
    return pub_key, pre


def get_login_form(session: requests.Session) -> dict[str, str]:
    """拉取 PC 统一登录页面并提取表单隐藏参数。"""
    resp = session.get(
        f"{WEB_URL}/api/portal/unifyLoginForPC.action",
        params={
            "appId": APP_ID,
            "clientType": CLIENT_TYPE,
            "returnURL": RETURN_URL,
            "timeStamp": int(time.time() * 1000),
        },
        timeout=15,
    )
    resp.raise_for_status()
    html = resp.text

    patterns = {
        "captchaToken": r"'captchaToken' value='(.+?)'",
        "lt": r'lt = "(.+?)"',
        "paramId": r'paramId = "(.+?)"',
        "reqId": r'reqId = "(.+?)"',
    }
    form_params: dict[str, str] = {}
    for key, pattern in patterns.items():
        match = re.search(pattern, html)
        if not match:
            raise RuntimeError(f"解析登录表单失败：页面缺少字段 {key}")
        form_params[key] = match.group(1)
    return form_params


def login_by_password(session: requests.Session, username: str, password: str) -> str:
    """使用账号密码完成统一认证登录并换取 sessionKey。"""
    pub_key, pre = get_encrypt_conf(session)
    form_params = get_login_form(session)

    form_data = {
        "appKey": APP_ID,
        "accountType": ACCOUNT_TYPE,
        "validateCode": "",
        "captchaToken": form_params["captchaToken"],
        "dynamicCheck": "FALSE",
        "clientType": "1",
        "cb_SaveName": "3",
        "isOauth2": "false",
        "returnUrl": RETURN_URL,
        "paramId": form_params["paramId"],
        "userName": f"{pre}{rsa_encrypt(pub_key, username)}",
        "password": f"{pre}{rsa_encrypt(pub_key, password)}",
    }
    login_resp = session.post(
        f"{AUTH_URL}/api/logbox/oauth2/loginSubmit.do",
        headers={
            "Referer": AUTH_URL,
            "lt": form_params["lt"],
            "REQID": form_params["reqId"],
        },
        data=form_data,
        timeout=15,
    )
    login_resp.raise_for_status()
    login_res = login_resp.json()

    if str(login_res.get("result")) != "0" or not login_res.get("toUrl"):
        raise RuntimeError(
            f"登录失败：result={login_res.get('result')}, msg={login_res.get('msg', '未知错误')}"
        )

    session_resp = session.post(
        f"{API_URL}/getSessionForPC.action",
        params={
            "appId": APP_ID,
            "clientType": "TELEPC",
            "version": "6.2",
            "channelId": "web_cloud.189.cn",
            "rand": str(int(time.time() * 1000)),
            "redirectURL": login_res["toUrl"],
        },
        timeout=15,
    )
    session_resp.raise_for_status()
    session_res = session_resp.json()
    _check_api_error(session_res, "换取会话")

    session_key = session_res.get("sessionKey")
    if not session_key:
        raise RuntimeError(f"换取会话失败：响应缺少 sessionKey（{session_res}）")
    return session_key


def _cloud_headers() -> dict[str, str]:
    """构造天翼云盘 Web 接口通用请求头。"""
    return {
        "Referer": f"{WEB_URL}/web/main/",
        "Accept": "application/json;charset=UTF-8",
    }


def get_user_size_info(session: requests.Session, session_key: str) -> dict:
    """获取账号个人及家庭空间容量信息。"""
    resp = session.get(
        f"{WEB_URL}/api/portal/getUserSizeInfo.action",
        params={"sessionKey": session_key},
        headers=_cloud_headers(),
        timeout=15,
    )
    resp.raise_for_status()
    data = resp.json()
    _check_api_error(data, "获取容量信息")
    return data


def user_sign(session: requests.Session, session_key: str) -> dict:
    """执行个人每日签到任务。"""
    resp = session.get(
        f"{WEB_URL}/mkt/userSign.action",
        params={
            "rand": str(int(time.time() * 1000)),
            "clientType": "TELEANDROID",
            "version": "9.0.6",
            "model": "KB2000",
            "sessionKey": session_key,
        },
        headers=_cloud_headers(),
        timeout=15,
    )
    resp.raise_for_status()
    data = resp.json()
    _check_api_error(data, "执行签到")
    return data


def _extract_totals(size_info: dict) -> tuple[int, int]:
    """提取个人总容量与家庭总容量（单位：字节）。"""
    cloud_total = size_info.get("cloudCapacityInfo", {}).get("totalSize", 0)
    family_total = size_info.get("familyCapacityInfo", {}).get("totalSize", 0)
    return int(cloud_total), int(family_total)


def run_account(index: int, username: str, password: str) -> None:
    """执行单个账号的登录、签到及容量变化统计。"""
    masked = mask_account(username)
    print(f"开始执行账号{index}（{masked}）")

    session = requests.Session()
    session.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "application/json;charset=UTF-8",
    })

    session_key = login_by_password(session, username, password)
    print("登录成功")

    before_cloud, before_family = _extract_totals(get_user_size_info(session, session_key))

    sign_res = user_sign(session, session_key)
    raw_is_sign = sign_res.get("isSign")
    already_signed = raw_is_sign is True or str(raw_is_sign).lower() == "true"
    bonus = sign_res.get("netdiskBonus", 0)
    if already_signed:
        print(f"今日已签到过了，今日奖励 {bonus}M 空间")
    else:
        print(f"签到成功，获得 {bonus}M 空间")

    after_cloud, after_family = _extract_totals(get_user_size_info(session, session_key))
    cloud_diff_mb = (after_cloud - before_cloud) / 1024 / 1024
    cloud_total_gb = after_cloud / 1024 / 1024 / 1024
    family_diff_mb = (after_family - before_family) / 1024 / 1024
    family_total_gb = after_family / 1024 / 1024 / 1024
    print(
        f"个人容量：+{cloud_diff_mb:.2f}M / 总计 {cloud_total_gb:.2f}G；"
        f"家庭容量：+{family_diff_mb:.2f}M / 总计 {family_total_gb:.2f}G"
    )


def main() -> None:
    """读取环境变量中的账号密码并批量执行签到。"""
    raw_users = os.getenv("TYYP_USERNAME", "")
    raw_passwords = os.getenv("TYYP_PSW", "")

    usernames = [u.strip() for u in raw_users.split("&") if u.strip()]
    passwords = [p.strip() for p in raw_passwords.split("&") if p.strip()]

    if not usernames or not passwords:
        print("错误：环境变量 TYYP_USERNAME 或 TYYP_PSW 未配置或为空", file=sys.stderr)
        sys.exit(1)

    if len(usernames) != len(passwords):
        print(
            f"错误：账号数量（{len(usernames)}）与密码数量（{len(passwords)}）不一致",
            file=sys.stderr,
        )
        sys.exit(1)

    failed_count = 0
    for idx, (username, password) in enumerate(zip(usernames, passwords), start=1):
        try:
            run_account(idx, username, password)
        except Exception as exc:
            failed_count += 1
            print(f"账号{idx}（{mask_account(username)}）执行失败：{exc}", file=sys.stderr)

    if failed_count > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
