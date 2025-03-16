# -*- coding: utf-8 -*-
import requests
from bs4 import BeautifulSoup
import re
import time
import os
import json
import base64
import urllib.parse
import random
from datetime import datetime
import logging
from requests.exceptions import RequestException, Timeout, ConnectionError

# 配置文件路径
CONFIG_FILE = 'config.json'

# 加载配置文件
def load_config():
    """加载配置文件"""
    try:
        if not os.path.exists(CONFIG_FILE):
            # 如果配置文件不存在，创建默认配置
            default_config = {
                "api": {
                    "baidu_ocr": {
                        "api_key": "你的百度OCR API Key",
                        "secret_key": "你的百度OCR Secret Key"
                    }
                },
                "request": {
                    "timeout": 30,
                    "max_retries": 3,
                    "retry_delay": 3,
                    "captcha_max_attempts": 3
                },
                "paths": {
                    "accounts_file": "accounts.json",
                    "cookies_dir": "cookies",
                    "logs_dir": "logs",
                    "history_file": "sign_history.json"
                },
                "sign": {
                    "account_delay": {
                        "min": 5,
                        "max": 10
                    },
                    "error_delay": {
                        "min": 10,
                        "max": 15
                    }
                }
            }
            with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                json.dump(default_config, f, ensure_ascii=False, indent=4)
            return default_config
            
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            config = json.load(f)
            
        return config
    except Exception as e:
        print(f"加载配置文件失败: {str(e)}，将使用默认配置")
        # 返回默认配置
        return {
            "api": {
                "baidu_ocr": {
                    "api_key": "你的百度OCR API Key",
                    "secret_key": "你的百度OCR Secret Key"
                }
            },
            "request": {
                "timeout": 30,
                "max_retries": 3,
                "retry_delay": 3,
                "captcha_max_attempts": 3
            },
            "paths": {
                "accounts_file": "accounts.json",
                "cookies_dir": "cookies",
                "logs_dir": "logs",
                "history_file": "sign_history.json"
            },
            "sign": {
                "account_delay": {
                    "min": 5,
                    "max": 10
                },
                "error_delay": {
                    "min": 10,
                    "max": 15
                }
            }
        }

# 加载配置
config = load_config()

# 从配置中获取参数
API_KEY = config["api"]["baidu_ocr"]["api_key"]
SECRET_KEY = config["api"]["baidu_ocr"]["secret_key"]

# 请求配置
REQUEST_TIMEOUT = config["request"]["timeout"]
MAX_RETRIES = config["request"]["max_retries"]
RETRY_DELAY = config["request"]["retry_delay"]
CAPTCHA_MAX_ATTEMPTS = config["request"]["captcha_max_attempts"]

# 路径配置
ACCOUNT_CONFIG_FILE = config["paths"]["accounts_file"]
COOKIES_DIR = config["paths"]["cookies_dir"]
LOGS_DIR = config["paths"]["logs_dir"]
HISTORY_FILE = config["paths"]["history_file"]

# 签到延迟配置
ACCOUNT_DELAY_MIN = config["sign"]["account_delay"]["min"]
ACCOUNT_DELAY_MAX = config["sign"]["account_delay"]["max"]
ERROR_DELAY_MIN = config["sign"]["error_delay"]["min"]
ERROR_DELAY_MAX = config["sign"]["error_delay"]["max"]

# 配置日志
def setup_logger():
    """配置日志记录器"""
    # 创建日志目录
    if not os.path.exists(LOGS_DIR):
        os.makedirs(LOGS_DIR)
    
    # 获取当前日期作为日志文件名
    current_date = datetime.now().strftime("%Y-%m-%d")
    log_file = f'{LOGS_DIR}/mt_sign_{current_date}.log'
    
    # 配置日志格式
    logger = logging.getLogger('mt_sign')
    logger.setLevel(logging.INFO)
    
    # 防止重复添加处理器
    if not logger.handlers:
        # 文件处理器
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.INFO)
        
        # 控制台处理器
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # 设置日志格式
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        # 添加处理器
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
    
    return logger

# 初始化日志
logger = setup_logger()

# 历史记录管理
class HistoryManager:
    def __init__(self):
        self.history_file = HISTORY_FILE
        self.history_data = self.load_history()
        
    def load_history(self):
        """加载历史记录"""
        try:
            if not os.path.exists(self.history_file):
                # 如果历史记录文件不存在，创建空记录
                default_history = {
                    "accounts": {},
                    "summary": {}
                }
                with open(self.history_file, 'w', encoding='utf-8') as f:
                    json.dump(default_history, f, ensure_ascii=False, indent=4)
                return default_history
                
            with open(self.history_file, 'r', encoding='utf-8') as f:
                history = json.load(f)
                
            return history
        except Exception as e:
            logger.error(f"加载历史记录失败: {str(e)}")
            # 返回空记录
            return {"accounts": {}, "summary": {}}
    
    def save_history(self):
        """保存历史记录"""
        try:
            with open(self.history_file, 'w', encoding='utf-8') as f:
                json.dump(self.history_data, f, ensure_ascii=False, indent=4)
            return True
        except Exception as e:
            logger.error(f"保存历史记录失败: {str(e)}")
            return False
    
    def add_sign_record(self, username, sign_data):
        """添加签到记录"""
        try:
            current_date = datetime.now().strftime("%Y-%m-%d")
            current_time = datetime.now().strftime("%H:%M:%S")
            
            # 确保账号记录存在
            if username not in self.history_data["accounts"]:
                self.history_data["accounts"][username] = {
                    "history": [],
                    "last_sign": "",
                    "consecutive_days": 0,
                    "total_days": 0
                }
            
            # 添加签到记录
            record = {
                "date": current_date,
                "time": current_time,
                "status": sign_data.get("status", "unknown"),
                "consecutive_days": int(sign_data.get("连续签到", 0)),
                "rank": int(sign_data.get("签到排名", 0)),
                "level": int(sign_data.get("签到等级", 0)),
                "reward": int(sign_data.get("积分奖励", 0)),
                "total_days": int(sign_data.get("总天数", 0))
            }
            
            # 更新账号信息
            self.history_data["accounts"][username]["history"].append(record)
            self.history_data["accounts"][username]["last_sign"] = current_date
            self.history_data["accounts"][username]["consecutive_days"] = int(sign_data.get("连续签到", 0))
            self.history_data["accounts"][username]["total_days"] = int(sign_data.get("总天数", 0))
            
            # 保存历史记录
            self.save_history()
            return True
        except Exception as e:
            logger.error(f"添加签到记录失败: {str(e)}")
            return False
    
    def add_daily_summary(self, summary_data):
        """添加每日签到汇总"""
        try:
            current_date = datetime.now().strftime("%Y-%m-%d")
            
            # 添加每日汇总
            self.history_data["summary"][current_date] = summary_data
            
            # 保存历史记录
            self.save_history()
            return True
        except Exception as e:
            logger.error(f"添加每日汇总失败: {str(e)}")
            return False
    
    def get_account_history(self, username):
        """获取账号签到历史"""
        try:
            if username in self.history_data["accounts"]:
                return self.history_data["accounts"][username]
            return None
        except Exception as e:
            logger.error(f"获取账号历史失败: {str(e)}")
            return None
    
    def get_daily_summary(self, date=None):
        """获取每日签到汇总"""
        try:
            if date is None:
                date = datetime.now().strftime("%Y-%m-%d")
                
            if date in self.history_data["summary"]:
                return self.history_data["summary"][date]
            return None
        except Exception as e:
            logger.error(f"获取每日汇总失败: {str(e)}")
            return None

# 初始化历史记录管理器
history_manager = HistoryManager()

class DzSigner:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Origin': 'https://bbs.binmt.cc',
            'Referer': 'https://bbs.binmt.cc/'
        })
        # 为每个账号单独保存cookie文件
        self.cookie_file = f'{COOKIES_DIR}/{username}_cookies.json'
        # 重试计数器
        self.retry_count = 0
        # 验证码识别尝试次数
        self.captcha_attempts = 0
        # 签到结果
        self.sign_result = {}

    def save_cookies(self):
        """保存Cookie到本地文件"""
        try:
            # 确保cookies目录存在
            os.makedirs(COOKIES_DIR, exist_ok=True)
            
            with open(self.cookie_file, 'w', encoding='utf-8') as f:
                json.dump(self.session.cookies.get_dict(), f)
            logger.info(f"[{self.username}] Cookie已保存到本地: {self.cookie_file}")
            return True
        except Exception as e:
            logger.error(f"[{self.username}] 保存Cookie失败: {str(e)}")
            return False

    def load_cookies(self):
        """从本地文件加载Cookie"""
        try:
            if not os.path.exists(self.cookie_file):
                logger.info(f"[{self.username}] 未找到Cookie文件，将进行账号登录")
                return False
                
            with open(self.cookie_file, 'r', encoding='utf-8') as f:
                cookies = json.load(f)
                
            for key, value in cookies.items():
                self.session.cookies.set(key, value)
                
            logger.info(f"[{self.username}] 已从本地加载Cookie: {self.cookie_file}")
            return True
        except Exception as e:
            logger.error(f"[{self.username}] 加载Cookie失败: {str(e)}")
            return False

    def check_login_status(self):
        """检查登录状态"""
        try:
            home_page = self.session.get('https://bbs.binmt.cc/', timeout=REQUEST_TIMEOUT)
            # 检查是否包含已登录的标识
            return '访问我的空间' in home_page.text and self.username in home_page.text
        except Timeout:
            logger.error(f"[{self.username}] 检查登录状态超时")
            return False
        except ConnectionError:
            logger.error(f"[{self.username}] 检查登录状态连接错误")
            return False
        except Exception as e:
            logger.error(f"[{self.username}] 检查登录状态失败: {str(e)}")
            return False

    def check_signed(self):
        """检测今日是否已签到"""
        for attempt in range(MAX_RETRIES):
            try:
                sign_page = self.session.get('https://bbs.binmt.cc/k_misign-sign.html', timeout=REQUEST_TIMEOUT)
                soup = BeautifulSoup(sign_page.text, 'html.parser')
                
                if soup.find('span', {'class': 'btnvisted'}):
                    return True
                    
                sign_button = soup.find('a', {'id': 'JD_sign'})
                if not sign_button or 'disabled' in sign_button.get('class', []):
                    return True
                    
                return "今日已签" in sign_page.text
                
            except Timeout:
                logger.warning(f"[{self.username}] 签到状态检测超时，第{attempt+1}次尝试")
            except ConnectionError:
                logger.warning(f"[{self.username}] 签到状态检测连接错误，第{attempt+1}次尝试")
            except Exception as e:
                logger.error(f"[{self.username}] 签到状态检测失败: {str(e)}")
                return False
                
            # 如果不是最后一次尝试，则等待后重试
            if attempt < MAX_RETRIES - 1:
                retry_delay = RETRY_DELAY + random.uniform(0, 2)  # 添加随机延迟
                logger.info(f"[{self.username}] {retry_delay:.2f}秒后重试...")
                time.sleep(retry_delay)
                
        logger.error(f"[{self.username}] 签到状态检测失败，已达到最大重试次数")
        return False

    def get_access_token(self):
        """获取百度OCR API的access_token"""
        for attempt in range(MAX_RETRIES):
            try:
                url = "https://aip.baidubce.com/oauth/2.0/token"
                params = {"grant_type": "client_credentials", "client_id": API_KEY, "client_secret": SECRET_KEY}
                response = requests.post(url, params=params, timeout=REQUEST_TIMEOUT)
                if response.status_code == 200 and "access_token" in response.json():
                    return str(response.json().get("access_token"))
                else:
                    logger.error(f"[{self.username}] 获取access_token失败: {response.text}")
            except Timeout:
                logger.warning(f"[{self.username}] 获取access_token超时，第{attempt+1}次尝试")
            except Exception as e:
                logger.error(f"[{self.username}] 获取access_token出错: {str(e)}")
                
            # 如果不是最后一次尝试，则等待后重试
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY)
                
        logger.error(f"[{self.username}] 获取access_token失败，已达到最大重试次数")
        return None

    def recognize_captcha(self, image_path):
        """识别验证码"""
        try:
            # 获取access_token
            access_token = self.get_access_token()
            if not access_token:
                return None
                
            url = f"https://aip.baidubce.com/rest/2.0/ocr/v1/accurate_basic?access_token={access_token}"
            
            # 读取图片并转为base64
            with open(image_path, "rb") as f:
                image_data = base64.b64encode(f.read()).decode("utf8")
                image_data = urllib.parse.quote_plus(image_data)
            
            # 构建请求
            payload = f'image={image_data}&detect_direction=false&paragraph=false&probability=false'
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json'
            }
            
            # 发送请求
            response = requests.request("POST", url, headers=headers, data=payload.encode("utf-8"), timeout=REQUEST_TIMEOUT)
            result = response.json()
            
            # 解析结果
            if 'words_result' in result and len(result['words_result']) > 0:
                captcha_text = result['words_result'][0]['words']
                # 清理验证码文本，移除空格和特殊字符
                captcha_text = re.sub(r'[\s+]', '', captcha_text)
                # 确保验证码只包含字母和数字
                captcha_text = re.sub(r'[^a-zA-Z0-9]', '', captcha_text)
                logger.info(f"[{self.username}] 验证码识别结果: {captcha_text}")
                return captcha_text
            else:
                logger.error(f"[{self.username}] 验证码识别失败: {result}")
                return None
        except Timeout:
            logger.error(f"[{self.username}] 验证码识别请求超时")
            return None
        except Exception as e:
            logger.error(f"[{self.username}] 验证码识别过程出错: {str(e)}")
            return None

    def download_captcha(self, soup):
        """下载验证码图片"""
        for attempt in range(MAX_RETRIES):
            try:
                # 查找验证码图片元素
                captcha_img = soup.find('img', {'src': re.compile(r'misc\.php\?mod=seccode')})
                if not captcha_img:
                    logger.error(f"[{self.username}] 未找到验证码图片")
                    return None
                    
                # 获取验证码图片URL
                captcha_url = 'https://bbs.binmt.cc/' + captcha_img['src']
                
                # 下载验证码图片
                captcha_response = self.session.get(captcha_url, timeout=REQUEST_TIMEOUT)
                if captcha_response.status_code != 200:
                    logger.error(f"[{self.username}] 下载验证码图片失败: {captcha_response.status_code}")
                    if attempt < MAX_RETRIES - 1:
                        logger.info(f"[{self.username}] 第{attempt+1}次尝试下载验证码图片...")
                        time.sleep(RETRY_DELAY)
                        continue
                    return None
                    
                # 保存验证码图片
                # 为避免多账号同时下载验证码冲突，使用用户名作为文件名前缀
                captcha_path = f'captcha_{self.username}.jpg'
                with open(captcha_path, 'wb') as f:
                    f.write(captcha_response.content)
                    
                logger.info(f"[{self.username}] 验证码图片已保存到: {captcha_path}")
                return captcha_path
            except Timeout:
                logger.warning(f"[{self.username}] 下载验证码图片超时，第{attempt+1}次尝试")
            except ConnectionError:
                logger.warning(f"[{self.username}] 下载验证码图片连接错误，第{attempt+1}次尝试")
            except Exception as e:
                logger.error(f"[{self.username}] 下载验证码图片失败: {str(e)}")
                return None
                
            # 如果不是最后一次尝试，则等待后重试
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY)
                
        logger.error(f"[{self.username}] 下载验证码图片失败，已达到最大重试次数")
        return None

    def login(self):
        """执行登录操作"""
        # 先尝试加载Cookie并检查登录状态
        if self.load_cookies() and self.check_login_status():
            logger.info(f"[{self.username}] 使用Cookie登录成功")
            return True
            
        logger.info(f"[{self.username}] Cookie无效或已过期，将使用账号密码登录")
        
        # 重置验证码尝试次数
        self.captcha_attempts = 0
        
        # 登录重试机制
        for login_attempt in range(MAX_RETRIES):
            try:
                login_page = self.session.get('https://bbs.binmt.cc/member.php?mod=logging&action=login', timeout=REQUEST_TIMEOUT)
                soup = BeautifulSoup(login_page.text, 'html.parser')
                
                username_input = soup.find('input', {'name': 'username'})
                password_input = soup.find('input', {'name': 'password'})
                
                if not username_input or not password_input:
                    logger.error(f"[{self.username}] 找不到登录表单元素")
                    return False

                login_data = {
                    'formhash': soup.find('input', {'name': 'formhash'})['value'],
                    'referer': 'https://bbs.binmt.cc/',
                    'username': self.username,
                    'password': self.password,
                    'cookietime': soup.find('input', {'name': 'cookietime'})['value'],
                    'loginsubmit': '登录'
                }

                login_data[username_input['id']] = self.username
                login_data[password_input['id']] = self.password

                # 检查是否需要验证码
                seccode_verify = soup.find('input', {'name': 'seccodeverify'})
                if seccode_verify:
                    logger.info(f"[{self.username}] 检测到需要输入验证码 (尝试 {self.captcha_attempts + 1}/{CAPTCHA_MAX_ATTEMPTS})")
                    
                    # 超过最大尝试次数
                    if self.captcha_attempts >= CAPTCHA_MAX_ATTEMPTS:
                        logger.error(f"[{self.username}] 验证码识别已达到最大尝试次数 {CAPTCHA_MAX_ATTEMPTS}")
                        return False
                    
                    self.captcha_attempts += 1
                    
                    # 下载验证码图片
                    captcha_path = self.download_captcha(soup)
                    if not captcha_path:
                        if login_attempt < MAX_RETRIES - 1:
                            logger.warning(f"[{self.username}] 验证码下载失败，{RETRY_DELAY}秒后重试...")
                            time.sleep(RETRY_DELAY)
                            continue
                        return False
                        
                    # 识别验证码
                    captcha_text = self.recognize_captcha(captcha_path)
                    if not captcha_text:
                        if login_attempt < MAX_RETRIES - 1:
                            logger.warning(f"[{self.username}] 验证码识别失败，{RETRY_DELAY}秒后重试...")
                            time.sleep(RETRY_DELAY)
                            continue
                        return False
                        
                    # 添加验证码到登录数据
                    idhash = seccode_verify['id'].replace('seccodeverify_', '')
                    login_data['seccodehash'] = idhash
                    login_data['seccodeverify'] = captcha_text

                # 发送登录请求
                login_res = self.session.post(
                    'https://bbs.binmt.cc/member.php?mod=logging&action=login&loginsubmit=yes&infloat=yes&handlekey=login',
                    data=login_data,
                    timeout=REQUEST_TIMEOUT
                )

                # 检查登录结果
                if '欢迎您回来' in login_res.text or self.check_login_status():
                    logger.info(f"[{self.username}] 登录成功")
                    # 保存Cookie
                    self.save_cookies()
                    return True
                    
                # 如果登录失败，检查是否是验证码错误
                if '验证码错误' in login_res.text and seccode_verify:
                    logger.warning(f"[{self.username}] 验证码识别错误，重新尝试")
                    # 不递归调用，而是继续循环重试
                    continue
                    
                logger.error(f"[{self.username}] 登录失败，请检查账号密码")
                return False
                
            except Timeout:
                logger.warning(f"[{self.username}] 登录请求超时，第{login_attempt+1}次尝试")
            except ConnectionError:
                logger.warning(f"[{self.username}] 登录连接错误，第{login_attempt+1}次尝试")
            except Exception as e:
                logger.error(f"[{self.username}] 登录过程出现错误: {str(e)}")
                return False
                
            # 如果不是最后一次尝试，则等待后重试
            if login_attempt < MAX_RETRIES - 1:
                retry_delay = RETRY_DELAY + random.uniform(0, 2)  # 添加随机延迟
                logger.info(f"[{self.username}] {retry_delay:.2f}秒后重试登录...")
                time.sleep(retry_delay)
                
        logger.error(f"[{self.username}] 登录失败，已达到最大重试次数 {MAX_RETRIES}")
        return False

    def get_formhash(self):
        """获取动态formhash值"""
        for attempt in range(MAX_RETRIES):
            try:
                if self.check_signed():
                    logger.info(f"[{self.username}] 今日已完成签到，无需重复操作")
                    return None
                    
                sign_page = self.session.get('https://bbs.binmt.cc/k_misign-sign.html', timeout=REQUEST_TIMEOUT)
                soup = BeautifulSoup(sign_page.text, 'html.parser')
                sign_button = soup.find('a', {'id': 'JD_sign'})
                
                if not sign_button:
                    logger.error(f"[{self.username}] 找不到签到按钮")
                    if attempt < MAX_RETRIES - 1:
                        logger.warning(f"[{self.username}] 第{attempt+1}次尝试获取formhash...")
                        time.sleep(RETRY_DELAY)
                        continue
                    return None
                    
                formhash_match = re.search(r'formhash=([a-f0-9]+)', sign_button['href'])
                if not formhash_match:
                    logger.error(f"[{self.username}] 无法从签到按钮中提取formhash")
                    if attempt < MAX_RETRIES - 1:
                        logger.warning(f"[{self.username}] 第{attempt+1}次尝试获取formhash...")
                        time.sleep(RETRY_DELAY)
                        continue
                    return None
                    
                formhash = formhash_match.group(1)
                logger.info(f"[{self.username}] 成功获取formhash: {formhash}")
                return formhash
                
            except Timeout:
                logger.warning(f"[{self.username}] 获取formhash超时，第{attempt+1}次尝试")
            except ConnectionError:
                logger.warning(f"[{self.username}] 获取formhash连接错误，第{attempt+1}次尝试")
            except Exception as e:
                logger.error(f"[{self.username}] 获取formhash失败: {str(e)}")
                return None
                
            # 如果不是最后一次尝试，则等待后重试
            if attempt < MAX_RETRIES - 1:
                retry_delay = RETRY_DELAY + random.uniform(0, 2)  # 添加随机延迟
                logger.info(f"[{self.username}] {retry_delay:.2f}秒后重试获取formhash...")
                time.sleep(retry_delay)
                
        logger.error(f"[{self.username}] 获取formhash失败，已达到最大重试次数")
        return None

    def sign(self):
        """执行签到操作"""
        if self.check_signed():
            logger.info(f"[{self.username}] 签到状态检测：今日已签到")
            return True

        formhash = self.get_formhash()
        if not formhash:
            return False

        for attempt in range(MAX_RETRIES):
            try:
                logger.info(f"[{self.username}] 正在执行签到操作 (尝试 {attempt+1}/{MAX_RETRIES})")
                res = self.session.get(
                    f'https://bbs.binmt.cc/plugin.php?id=k_misign:sign&operation=qiandao&formhash={formhash}&format=empty',
                    headers={'X-Requested-With': 'XMLHttpRequest'},
                    timeout=REQUEST_TIMEOUT
                )
                
                if res.status_code == 200:
                    # 等待一段时间，确保签到状态更新
                    wait_time = 1.5 + random.uniform(0, 1)  # 添加随机延迟
                    logger.info(f"[{self.username}] 签到请求成功，等待 {wait_time:.2f} 秒后检查签到状态...")
                    time.sleep(wait_time)
                    
                    # 检查签到是否成功
                    if self.check_signed():
                        logger.info(f"[{self.username}] 签到成功确认")
                        return True
                    else:
                        logger.warning(f"[{self.username}] 签到请求已发送，但签到状态未更新")
                        if attempt < MAX_RETRIES - 1:
                            logger.info(f"[{self.username}] 将重试签到操作...")
                            continue
                else:
                    logger.error(f"[{self.username}] 签到请求返回状态码: {res.status_code}")
                    if attempt < MAX_RETRIES - 1:
                        logger.info(f"[{self.username}] 将重试签到操作...")
                        continue
                    
            except Timeout:
                logger.warning(f"[{self.username}] 签到请求超时，第{attempt+1}次尝试")
            except ConnectionError:
                logger.warning(f"[{self.username}] 签到请求连接错误，第{attempt+1}次尝试")
            except Exception as e:
                logger.error(f"[{self.username}] 签到请求失败: {str(e)}")
                return False
                
            # 如果不是最后一次尝试，则等待后重试
            if attempt < MAX_RETRIES - 1:
                retry_delay = RETRY_DELAY + random.uniform(0, 2)  # 添加随机延迟
                logger.info(f"[{self.username}] {retry_delay:.2f}秒后重试签到...")
                time.sleep(retry_delay)
                
        logger.error(f"[{self.username}] 签到失败，已达到最大重试次数")
        return False
            
    def get_stats(self):
        """获取签到统计数据"""
        for attempt in range(MAX_RETRIES):
            try:
                sign_page = self.session.get('https://bbs.binmt.cc/k_misign-sign.html', timeout=REQUEST_TIMEOUT)
                soup = BeautifulSoup(sign_page.text, 'html.parser')
                
                stats = {}
                stats_fields = {
                    '连续签到': 'lxdays',
                    '签到等级': 'lxlevel',
                    '积分奖励': 'lxreward',
                    '总天数': 'lxtdays',
                    '签到排名': 'qiandaobtnnum'
                }
                
                # 逐个获取统计数据，避免一个字段出错导致整个统计失败
                for label, field_id in stats_fields.items():
                    try:
                        field = soup.find('input', {'id': field_id})
                        if field and 'value' in field.attrs:
                            stats[label] = field['value']
                        else:
                            stats[label] = 'N/A'
                    except Exception as e:
                        logger.warning(f"[{self.username}] 获取{label}失败: {str(e)}")
                        stats[label] = 'N/A'
                
                # 检查是否获取到了所有字段
                if all(value != 'N/A' for value in stats.values()):
                    return stats
                else:
                    logger.warning(f"[{self.username}] 部分统计数据获取失败: {stats}")
                    if attempt < MAX_RETRIES - 1:
                        logger.info(f"[{self.username}] 将重试获取统计数据...")
                        time.sleep(RETRY_DELAY)
                        continue
                    return stats
                    
            except Timeout:
                logger.warning(f"[{self.username}] 获取统计数据超时，第{attempt+1}次尝试")
            except ConnectionError:
                logger.warning(f"[{self.username}] 获取统计数据连接错误，第{attempt+1}次尝试")
            except Exception as e:
                logger.warning(f"[{self.username}] 获取统计信息失败: {str(e)}")
                return {}
                
            # 如果不是最后一次尝试，则等待后重试
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY)
                
        logger.warning(f"[{self.username}] 获取统计数据失败，已达到最大重试次数")
        return {}

    def run(self):
        """主运行流程"""
        current_date = datetime.now().strftime("%Y-%m-%d")
        logger.info(f"[{self.username}] 开始执行MT论坛自动签到 - {current_date}")
        start_time = time.time()
        
        try:
            # 登录
            logger.info(f"[{self.username}] 正在执行登录...")
            if not self.login():
                logger.error(f"[{self.username}] 登录失败，请检查账号密码或网络连接")
                return False
            
            # 检查是否已签到
            logger.info(f"[{self.username}] 正在检查签到状态...")
            if self.check_signed():
                logger.info(f"[{self.username}] 今日已完成签到，无需重复操作")
                # 获取签到统计信息
                stats = self.get_stats()
                if stats:
                    # 添加状态标记
                    stats['status'] = 'success'
                    
                    summary_message = (
                        f"连续签到: {stats.get('连续签到', 'N/A')} 天\n"
                        f"今日排名: 第{stats.get('签到排名', 'N/A')} 位\n"
                        f"签到等级: Lv{stats.get('签到等级', 'N/A')}\n"
                        f"本次积分: +{stats.get('积分奖励', 'N/A')}\n"
                        f"总签到天数: {stats.get('总天数', 'N/A')} 天"
                    )
                    logger.info(f"[{self.username}] === 签到信息 ===\n{summary_message}")
                    
                    # 添加到历史记录
                    history_manager.add_sign_record(self.username, stats)
                    
                return True
                
            # 执行签到
            logger.info(f"[{self.username}] 正在执行签到...")
            if self.sign():
                logger.info(f"[{self.username}] === 签到信息 ===")
                stats = self.get_stats()
                
                # 添加状态标记
                if stats:
                    stats['status'] = 'success'
                    
                    summary_message = (
                        f"连续签到: {stats.get('连续签到', 'N/A')} 天\n"
                        f"今日排名: 第{stats.get('签到排名', 'N/A')} 位\n"
                        f"签到等级: Lv{stats.get('签到等级', 'N/A')}\n"
                        f"本次积分: +{stats.get('积分奖励', 'N/A')}\n"
                        f"总签到天数: {stats.get('总天数', 'N/A')} 天"
                    )
                    logger.info(f"[{self.username}] {summary_message}")
                    
                    # 添加到历史记录
                    history_manager.add_sign_record(self.username, stats)
                
                # 计算耗时
                elapsed_time = time.time() - start_time
                logger.info(f"[{self.username}] 签到任务完成，耗时: {elapsed_time:.2f}秒")
                return True
            else:
                logger.warning(f"[{self.username}] 签到未完成，可能已签到或出现异常")
                # 添加失败记录
                failed_stats = {'status': 'failed'}
                history_manager.add_sign_record(self.username, failed_stats)
                return False
                
        except Exception as e:
            logger.error(f"[{self.username}] 签到过程出现未处理的异常: {str(e)}")
            # 添加异常记录
            error_stats = {'status': 'error', 'message': str(e)}
            history_manager.add_sign_record(self.username, error_stats)
            return False
        finally:
            # 计算总耗时
            total_time = time.time() - start_time
            logger.info(f"[{self.username}] 签到任务结束，总耗时: {total_time:.2f}秒")
            
def load_accounts():
    """从配置文件加载账号信息"""
    try:
        if not os.path.exists(ACCOUNT_CONFIG_FILE):
            # 如果配置文件不存在，创建一个示例配置
            example_accounts = [
                {"username": "用户名1", "password": "密码1"},
                {"username": "用户名2", "password": "密码2"}
            ]
            with open(ACCOUNT_CONFIG_FILE, 'w', encoding='utf-8') as f:
                json.dump(example_accounts, f, ensure_ascii=False, indent=4)
            logger.warning(f"账号配置文件不存在，已创建示例配置文件: {ACCOUNT_CONFIG_FILE}")
            logger.warning(f"请修改配置文件后重新运行程序")
            return []
            
        with open(ACCOUNT_CONFIG_FILE, 'r', encoding='utf-8') as f:
            accounts = json.load(f)
            
        if not accounts:
            logger.warning(f"账号配置文件为空，请添加账号信息")
            return []
            
        logger.info(f"成功加载 {len(accounts)} 个账号")
        return accounts
    except Exception as e:
        logger.error(f"加载账号配置失败: {str(e)}")
        return []

def run_multi_sign():
    """执行多账号签到"""
    # 加载账号信息
    accounts = load_accounts()
    if not accounts:
        return
        
    current_date = datetime.now().strftime("%Y-%m-%d")
    logger.info(f"===== 开始执行MT论坛多账号自动签到 - {current_date} =====")
    
    success_count = 0
    fail_count = 0
    total_rewards = 0
    start_time = time.time()
    
    # 循环执行每个账号的签到
    for i, account in enumerate(accounts):
        try:
            username = account.get('username')
            password = account.get('password')
            
            if not username or not password:
                logger.error(f"账号信息不完整，跳过: {account}")
                fail_count += 1
                continue
                
            logger.info(f"正在处理第 {i+1}/{len(accounts)} 个账号: {username}")
            
            # 创建签到实例并执行
            signer = DzSigner(username, password)
            result = signer.run()
            
            if result:
                success_count += 1
                # 获取账号历史记录，提取积分奖励
                account_history = history_manager.get_account_history(username)
                if account_history and account_history['history']:
                    latest_record = account_history['history'][-1]
                    reward = latest_record.get('reward', 0)
                    total_rewards += reward
            else:
                fail_count += 1
                
            # 每个账号之间添加随机延迟，避免触发网站反爬机制
            # 最后一个账号不需要等待
            if i < len(accounts) - 1:
                # 随机延迟
                delay = random.uniform(ACCOUNT_DELAY_MIN, ACCOUNT_DELAY_MAX)
                logger.info(f"等待 {delay:.2f} 秒后处理下一个账号...")
                time.sleep(delay)
                
        except Exception as e:
            logger.error(f"处理账号 {account.get('username', '未知')} 时出现未捕获的异常: {str(e)}")
            fail_count += 1
            # 出现异常时，添加额外延迟，避免连续请求失败
            if i < len(accounts) - 1:
                delay = random.uniform(ERROR_DELAY_MIN, ERROR_DELAY_MAX)
                logger.info(f"出现异常，等待 {delay:.2f} 秒后继续...")
                time.sleep(delay)
    
    # 计算总耗时
    total_time = time.time() - start_time
    
    # 输出签到统计信息
    logger.info(f"===== MT论坛多账号签到完成 - {current_date} =====")
    logger.info(f"总账号数: {len(accounts)}")
    logger.info(f"成功签到: {success_count}")
    logger.info(f"签到失败: {fail_count}")
    logger.info(f"总积分奖励: {total_rewards}")
    logger.info(f"总耗时: {total_time:.2f}秒")
    
    # 添加每日汇总到历史记录
    summary_data = {
        "total_accounts": len(accounts),
        "success_count": success_count,
        "fail_count": fail_count,
        "total_rewards": total_rewards,
        "execution_time": round(total_time, 2)
    }
    history_manager.add_daily_summary(summary_data)
    
    return success_count > 0  # 返回是否至少有一个账号签到成功

if __name__ == '__main__':
    run_multi_sign()

def sign(self):
    """执行签到操作"""
    start_time = time.time()
    sign_url = 'https://bbs.binmt.cc/k_misign-sign.html'
    
    for attempt in range(MAX_RETRIES):
        try:
            sign_res = self.session.get(sign_url, timeout=REQUEST_TIMEOUT)
            
            # 检查签到结果
            if '签到成功' in sign_res.text:
                # 解析签到结果
                sign_data = {}
                pattern = r'已连续签到(\d+)天，本次签到获得(\d+)积分，总共已签到(\d+)天，签到排名(\d+)，签到等级(\d+)'
                match = re.search(pattern, sign_res.text)
                
                if match:
                    sign_data = {
                        'status': '成功',
                        '连续签到': match.group(1),
                        '积分奖励': match.group(2),
                        '总天数': match.group(3),
                        '签到排名': match.group(4),
                        '签到等级': match.group(5)
                    }
                    
                    # 记录签到结果
                    self.sign_result = sign_data
                    
                    # 添加到历史记录
                    history_manager.add_sign_record(self.username, sign_data)
                    
                    logger.info(f"[{self.username}] 签到成功! 连续签到{match.group(1)}天，获得{match.group(2)}积分，总共已签到{match.group(3)}天，排名{match.group(4)}，等级{match.group(5)}")
                    return True
                else:
                    logger.info(f"[{self.username}] 签到成功，但无法解析详细信息: {sign_res.text}")
                    
                    # 记录基本签到结果
                    sign_data = {'status': '成功'}
                    self.sign_result = sign_data
                    
                    # 添加到历史记录
                    history_manager.add_sign_record(self.username, sign_data)
                    
                    return True
            elif '已经签到' in sign_res.text:
                logger.info(f"[{self.username}] 今日已签到，无需重复操作")
                
                # 记录已签到结果
                sign_data = {'status': '已签到'}
                self.sign_result = sign_data
                
                return True
            else:
                logger.error(f"[{self.username}] 签到失败: {sign_res.text}")
                return False
                
        except Timeout:
            logger.warning(f"[{self.username}] 签到请求超时，第{attempt+1}次尝试")
        except ConnectionError:
            logger.warning(f"[{self.username}] 签到连接错误，第{attempt+1}次尝试")
        except Exception as e:
            logger.error(f"[{self.username}] 签到过程出现错误: {str(e)}")
            
        # 如果不是最后一次尝试，则等待后重试
        if attempt < MAX_RETRIES - 1:
            retry_delay = RETRY_DELAY + random.uniform(0, 2)  # 添加随机延迟
            logger.info(f"[{self.username}] {retry_delay:.2f}秒后重试签到...")
            time.sleep(retry_delay)
            
    logger.error(f"[{self.username}] 签到失败，已达到最大重试次数")
    return False
