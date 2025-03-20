# MT_AQ -MT论坛自动签到脚本

## 项目简介

这是一个用于MT论坛自动签到的Python脚本，支持多账号管理、验证码自动识别和错误重试等功能。

### 主要功能

- 多账号管理和自动签到
- 百度OCR API自动识别验证码
- 支持安全提问设置
- 智能延迟和重试机制
- 详细的日志记录
- 签到历史和积分统计
- 智能Cookie管理和自动更新
- 灵活的配置选项
- 错误重试机制

## 环境要求

- Python 3.6 或更高版本
- 百度OCR API 账号（用于验证码识别）

## 安装说明

1. 确保已安装Python 3.6或更高版本
2. 安装所需依赖包：
```bash
pip install requests beautifulsoup4
```

## 配置说明

### 1. 账号配置
在`accounts.json`文件中配置账号信息：
```json
[
    {
        "username": "你的用户名",
        "password": "你的密码",
        "questionid": 0,  // 安全提问ID，默认为0
        "answer": ""     // 安全提问答案，默认为空
    }
]
```
0-安全提问(未设置请忽略)
1-母亲的名字
2-爷爷的名字
3-父亲出生的城市
4-您其中一位老师的名字
5-您个人计算机的型号
6-您最喜欢的餐馆名称
7-驾驶执照最后四位数字

### 2. 验证码识别配置
在`config.json`文件中配置百度OCR API信息：
```json
{
    "API_KEY": "你的百度OCR API Key",
    "SECRET_KEY": "你的百度OCR Secret Key"
}
```

### 3. 其他配置项
可在`config_manager.py`中调整以下参数：
- 账号间隔延迟时间
- 错误重试次数
- 超时设置
- 日志配置

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
