# 微信 PC（Weixin 4.x）本地图片 .dat 解密工具

从微信进程提取 V2 图片 AES 密钥，批量把聊天图片 `.dat` 解密为可打开的图片；带简单 GUI，可按聊天/月份选择导出。

> 仅用于导出**你自己账号**的本地数据。请遵守法律法规与微信用户协议。

## 功能

- 支持旧版 XOR / V1 / V2（`07 08 V2 08 07`）图片 `.dat`
- `monitor-key`：监控 `Weixin.exe` 内存，抓取 V2 AES 密钥并写入 `config.json`
- 命令行批量解密 / GUI 选择聊天与月份
- 可选：数据库密钥扫描与消息侧导出（实验中，见 `scan_db_keys.py` / `pipeline_db.py`）

## 环境

- Windows 10/11
- Python 3.10+
- 已登录的微信 4.x（进程名 `Weixin.exe`）

```bat
cd /d <本仓库目录>
py -3 -m pip install -r requirements.txt
copy config.example.json config.json
```

按需编辑 `config.json` 里的 `attach_dir`（你的 `xwechat_files\<wxid>\msg\attach`）。

依赖也可放到本地 `.deps`（已 gitignore）：

```bat
py -3 -m pip install -r requirements.txt -t .deps
```

`upstream/` 来自 [ZedeX/weixin-decrypte-script](https://github.com/ZedeX/weixin-decrypte-script)，用于解密核心与密钥扫描参考。

## 用法

### 1. 抓取图片密钥（首次或密钥失效时）

```bat
py -3 wechat_img.py monitor-key
```

保持微信登录，在任意聊天里点开 2～3 张大图；终端提示已保存后即可。也可双击 `1_抓密钥.bat`。

### 2. GUI 选择聊天导出

```bat
py -3 gui_picker.py
```

或双击 `启动解密.bat` / `launch_gui.bat`。

### 3. 命令行解密

```bat
py -3 wechat_img.py decrypt "<attach下某聊天或某月Img目录>" -o output\out
py -3 wechat_img.py show-config
```

## 说明

| 格式 | 文件头 | 处理 |
|------|--------|------|
| 旧 XOR | 无固定头 | 自动检测 |
| V1 | `07 08 V1 08 07` | 固定 AES key |
| V2 | `07 08 V2 08 07` | 需从进程内存提取 AES key |

微信默认常只缓存缩略图（`_t.dat`）；未点开过大图的原图需要先在客户端下载，或后续走「消息库 + CDN」补全（实验脚本已放仓库，数据库密钥提取通常需要管理员权限）。

## 隐私

- **不要**把含真实 `aes_key` / `db_key` / 聊天路径的 `config.json` 提交到 Git
- `output/`、`decrypted/` 含个人聊天媒体与库，已忽略

## License

本仓库自有脚本请自行负责使用方式。`upstream/` 遵循其原项目许可与声明。
