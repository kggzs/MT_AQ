# MT_AQ -MT论坛自动签到脚本

## 项目简介

这是一个用于MT论坛自动签到的Python脚本，支持多账号管理、验证码自动识别和错误重试等功能。

### 主要功能

- 支持多账号自动签到
- 使用百度OCR API自动识别验证码
- 智能Cookie管理和自动更新
- 详细的日志记录
- 灵活的配置选项
- 错误重试机制

## 环境要求

- Python 3.6 或更高版本
- 百度OCR API 账号（用于验证码识别）

## 依赖安装

1. 克隆或下载项目到本地

2. 安装所需的Python包：
```bash
pip install requests
pip install Pillow
pip install baidu-aip
```

## 配置说明

### 配置文件 (config.json)

配置文件包含以下主要部分：

1. API配置
```json
"api": {
    "baidu_ocr": {
        "api_key": "你的百度OCR API Key",
        "secret_key": "你的百度OCR Secret Key"
    }
}
```

2. 请求配置
```json
"request": {
    "timeout": 30,        // 请求超时时间（秒）
    "max_retries": 3,     // 最大重试次数
    "retry_delay": 3,     // 重试间隔时间（秒）
    "captcha_max_attempts": 3  // 验证码识别最大尝试次数
}
```

3. 路径配置
```json
"paths": {
    "accounts_file": "accounts.json",  // 账号配置文件
    "cookies_dir": "cookies",         // Cookie存储目录
    "logs_dir": "logs",              // 日志存储目录
    "history_file": "sign_history.json" // 签到历史记录
}
```

4. 签到配置
```json
"sign": {
    "account_delay": {     // 不同账号间的签到延迟（分钟）
        "min": 5,
        "max": 10
    },
    "error_delay": {       // 出错重试延迟（分钟）
        "min": 10,
        "max": 15
    }
}
```

### 账号配置 (accounts.json)

在accounts.json中配置你的MT论坛账号：

```json
[
    {
        "username": "你的用户名",
        "password": "你的密码"
    },
    {
        "username": "其他用户名",
        "password": "其他密码"
    }
]
```

## 使用方法

组合模式（推荐）
```bash
python mt_combined.py
```

## 日志说明

- 脚本会在logs目录下生成日志文件
- 日志文件名格式：mt_sign_YYYY-MM-DD.log
- 记录签到过程、错误信息和重试情况

## 常见问题

1. **验证码识别失败**
   - 确保百度OCR API配置正确
   - 检查API额度是否用尽
   - 可以适当增加重试次数

2. **Cookie失效**
   - 脚本会自动重新登录获取新Cookie
   - 确保账号密码正确

3. **签到失败**
   - 检查网络连接
   - 查看日志文件了解具体原因
   - 可能需要调整重试参数

## 更新日志

### 验证码处理
- 添加了验证码检测和下载功能
- 集成了百度OCR API进行验证码识别
- 实现了验证码识别失败后的自动重试机制

### Cookie管理功能
- 添加了Cookie保存到本地文件的功能
- 实现了从本地文件加载Cookie的功能
- 增加了Cookie有效性检查，失效时自动使用账号密码重新登录

### 用户体验优化
- 添加了详细的日志输出，方便用户了解脚本执行状态
- 优化了错误处理，提高了脚本的稳定性

## 免责声明

本脚本仅供学习交流使用，请勿用于商业用途。使用本脚本产生的任何后果由使用者自行承担。
```

### 注意事项

- 由于网站结构可能发生变化，如果脚本不能正常工作，请检查网页源代码是否有更新，并相应地调整脚本中的选择器。
- 请妥善保管你的账户信息，避免泄露。
