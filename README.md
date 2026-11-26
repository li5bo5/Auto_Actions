# [![云盘签到](https://github.com/li5bo5/Auto_Actions/actions/workflows/checkin.yml/badge.svg)](https://github.com/li5bo5/Auto_Actions/actions/workflows/checkin.yml)

### 使用方法

在仓库 **Settings -> Secrets and variables -> Actions** 中配置以下密钥：

#### 必填项
> - `CLOUD_USERNAME` : 账号（手机号），多个使用 `&` 分隔。比如：`19900000000&19900000001&19900000002`
> - `CLOUD_PASSWORD` : 密码，原密码中不能包含 `&`，否则会被识别为分隔符。比如：`PASSWORD0000&PASSWORD0001&PASSWORD0002`

多个账号密码按照顺序分别对应，比如：上面的 `PASSWORD0001` 对应 `19900000001`。

#### 可选项（Telegram 机器人推送）
> - `TG_BOT_TOKEN` : Telegram 机器人 Token（从 `@BotFather` 获取）
> - `TG_CHAT_ID` : 接收通知的 Telegram 用户 / 群组 Chat ID
> - `PUSH_ENABLED` : 是否启用推送，默认 `true`（设为 `false` 可临时关闭推送）
