# -*- coding: utf-8 -*-
"""天翼云盘自动签到脚本（支持断连自动重试与 Telegram 机器人推送）。"""

from datetime import datetime, timedelta, timezone
import os
import re
import sys
import time
import rsa
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

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

# 单账号遇到网络异常（如 RemoteDisconnected / 超时）时的最大整轮重连次数
MAX_NETWORK_RETRIES = 3

# Telegram 推送配置（与恩山签到保持一致）
PUSH_ENABLED = os.environ.get("PUSH_ENABLED", "true").strip().lower() == "true"
TG_BOT_TOKEN = os.environ.get("TG_BOT_TOKEN", "").strip()
TG_CHAT_ID = os.environ.get("TG_CHAT_ID", "").strip()


def log_err(msg: str) -> None:
    """输出诊断与推送状态信息到 stderr，避免写入公开的 STATUS.md。"""
    if TG_BOT_TOKEN:
        msg = msg.replace(TG_BOT_TOKEN, "***")
    print(msg, file=sys.stderr, flush=True)


def build_session() -> requests.Session:
    """创建带有底层自动重试策略的 HTTP 会话。"""
    session = requests.Session()
    retry_strategy = Retry(
        total=3,
        connect=3,
        read=3,
        status=3,
        backoff_factor=1.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=None,
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "application/json;charset=UTF-8",
    })
    return session


def push_telegram(text: str) -> None:
    """推送签到结果通知到 Telegram 机器人。"""
    if not PUSH_ENABLED:
        log_err("[推送] PUSH_ENABLED=false，已禁用推送")
        return
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        log_err("[推送] 未配置 TG_BOT_TOKEN 或 TG_CHAT_ID，跳过 Telegram 推送")
        return

    url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage"
    data = {
        "chat_id": TG_CHAT_ID,
        "text": text,
    }
    try:
        with build_session() as tg_session:
            resp = tg_session.post(url, json=data, timeout=15)
            res = resp.json()
        if res.get("ok"):
            log_err("[推送] Telegram 推送成功")
        else:
            log_err(f"[推送] Telegram 推送失败: {res}")
    except Exception as exc:
        log_err(f"[推送] Telegram 推送异常: {exc}")


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
    resp = session.post(f"{AUTH_URL}/api/logbox/config/encryptConf.do", timeout=20)
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
        timeout=20,
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
        timeout=20,
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
        timeout=20,
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
        timeout=20,
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
        timeout=20,
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


def _run_account_once(username: str, password: str) -> tuple[str, str]:
    """单次尝试执行登录、签到与容量统计，返回（签到结果描述，容量统计描述）。"""
    with build_session() as session:
        session_key = login_by_password(session, username, password)

        before_totals: tuple[int, int] | None = None
        try:
            before_totals = _extract_totals(get_user_size_info(session, session_key))
        except Exception as exc:
            log_err(f"[提示] 签到前容量查询异常（不影响签到）：{exc}")

        sign_res = user_sign(session, session_key)
        raw_is_sign = sign_res.get("isSign")
        already_signed = raw_is_sign is True or str(raw_is_sign).lower() == "true"
        bonus = sign_res.get("netdiskBonus", 0)
        if already_signed:
            sign_msg = f"今日已签到过了，今日奖励 {bonus}M 空间"
        else:
            sign_msg = f"签到成功，获得 {bonus}M 空间"

        capacity_msg = ""
        try:
            after_cloud, after_family = _extract_totals(get_user_size_info(session, session_key))
            cloud_total_gb = after_cloud / 1024 / 1024 / 1024
            family_total_gb = after_family / 1024 / 1024 / 1024
            if before_totals is not None:
                before_cloud, before_family = before_totals
                cloud_diff_mb = (after_cloud - before_cloud) / 1024 / 1024
                family_diff_mb = (after_family - before_family) / 1024 / 1024
                capacity_msg = (
                    f"个人容量：+{cloud_diff_mb:.2f}M / 总计 {cloud_total_gb:.2f}G；"
                    f"家庭容量：+{family_diff_mb:.2f}M / 总计 {family_total_gb:.2f}G"
                )
            else:
                capacity_msg = f"个人总容量：{cloud_total_gb:.2f}G；家庭总容量：{family_total_gb:.2f}G"
        except Exception as exc:
            log_err(f"[提示] 签到后容量查询异常（不影响签到结果）：{exc}")

        return sign_msg, capacity_msg


def run_account(index: int, username: str, password: str) -> dict:
    """带断连重建重试的单账号签到入口。"""
    masked = mask_account(username)
    print(f"开始执行账号{index}（{masked}）", flush=True)

    last_exc: Exception | None = None
    for attempt in range(1, MAX_NETWORK_RETRIES + 1):
        try:
            sign_msg, capacity_msg = _run_account_once(username, password)
            print("登录成功", flush=True)
            print(sign_msg, flush=True)
            if capacity_msg:
                print(capacity_msg, flush=True)
            return {
                "index": index,
                "masked": masked,
                "success": True,
                "sign_msg": sign_msg,
                "capacity_msg": capacity_msg,
                "error": "",
            }
        except requests.RequestException as exc:
            last_exc = exc
            if attempt < MAX_NETWORK_RETRIES:
                wait_sec = 3 * attempt
                log_err(
                    f"[重试] 账号{index}（{masked}）第 {attempt}/{MAX_NETWORK_RETRIES} 次请求遇到网络异常：{exc}，"
                    f"{wait_sec} 秒后重建连接重试..."
                )
                time.sleep(wait_sec)
            else:
                log_err(f"[失败] 账号{index}（{masked}）已达最大网络重试次数（{MAX_NETWORK_RETRIES} 次）")
        except Exception as exc:
            # 业务类错误（如密码错误、风控拦截）不重复提交，以免触发锁号
            last_exc = exc
            break

    err_text = str(last_exc)
    log_err(f"账号{index}（{masked}）执行失败：{err_text}")
    return {
        "index": index,
        "masked": masked,
        "success": False,
        "sign_msg": "",
        "capacity_msg": "",
        "error": err_text,
    }


def format_push_message(results: list[dict], now_str: str) -> str:
    """按恩山签到同款风格构造 Telegram 汇总通知文本。"""
    all_ok = bool(results) and all(item["success"] for item in results)
    header = "✅ 天翼云盘签到成功" if all_ok else "❌ 天翼云盘签到失败"

    blocks = [header, f"签到时间: {now_str}"]
    for item in results:
        title = f"账号{item['index']} ({item['masked']})"
        if item["success"]:
            lines = [title, f"✅ {item['sign_msg']}"]
            if item["capacity_msg"]:
                lines.append(f"📊 {item['capacity_msg']}")
        else:
            lines = [title, f"❌ 原因: {item['error']}"]
        blocks.append("\n".join(lines))

    return "\n\n".join(blocks)


def main() -> None:
    """读取环境变量中的账号密码，批量执行签到并推送通知。"""
    cst = timezone(timedelta(hours=8))
    now_str = datetime.now(cst).strftime("%Y-%m-%d %H:%M:%S")

    raw_users = os.getenv("TYYP_USERNAME", "")
    raw_passwords = os.getenv("TYYP_PSW", "")

    usernames = [u.strip() for u in raw_users.split("&") if u.strip()]
    passwords = [p.strip() for p in raw_passwords.split("&") if p.strip()]

    if not usernames or not passwords:
        err = "环境变量 TYYP_USERNAME 或 TYYP_PSW 未配置或为空"
        log_err(f"错误：{err}")
        push_telegram(f"❌ 天翼云盘签到失败\n\n签到时间: {now_str}\n\n原因: {err}")
        sys.exit(1)

    if len(usernames) != len(passwords):
        err = f"账号数量（{len(usernames)}）与密码数量（{len(passwords)}）不一致"
        log_err(f"错误：{err}")
        push_telegram(f"❌ 天翼云盘签到失败\n\n签到时间: {now_str}\n\n原因: {err}")
        sys.exit(1)

    results: list[dict] = []
    for idx, (username, password) in enumerate(zip(usernames, passwords), start=1):
        results.append(run_account(idx, username, password))

    summary_msg = format_push_message(results, now_str)
    push_telegram(summary_msg)

    if any(not item["success"] for item in results):
        sys.exit(1)


if __name__ == "__main__":
    main()
