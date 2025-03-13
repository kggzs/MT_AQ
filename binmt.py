# -*- coding: utf-8 -*-
import requests
from bs4 import BeautifulSoup
import re
import time
from datetime import datetime  # 新增日期模块

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

    def check_signed(self):
        """检测今日是否已签到"""
        try:
            sign_page = self.session.get('https://bbs.binmt.cc/k_misign-sign.html')
            soup = BeautifulSoup(sign_page.text, 'html.parser')
            
            if soup.find('span', {'class': 'btnvisted'}):
                return True
                
            sign_button = soup.find('a', {'id': 'JD_sign'})
            if not sign_button or 'disabled' in sign_button.get('class', []):
                return True
                
            return "今日已签" in sign_page.text
            
        except Exception as e:
            print(f"[异常] 签到状态检测失败: {str(e)}")
            return False

    def login(self):
        """执行登录操作"""
        try:
            login_page = self.session.get('https://bbs.binmt.cc/member.php?mod=logging&action=login')
            soup = BeautifulSoup(login_page.text, 'html.parser')
            
            username_input = soup.find('input', {'name': 'username'})
            password_input = soup.find('input', {'name': 'password'})
            
            if not username_input or not password_input:
                print("[错误] 找不到登录表单元素")
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

            login_res = self.session.post(
                'https://bbs.binmt.cc/member.php?mod=logging&action=login&loginsubmit=yes&infloat=yes&handlekey=login',
                data=login_data
            )

            if '欢迎您回来' in login_res.text:
                print("[成功] 登录成功")
                return True
            print("[失败] 登录失败，请检查账号密码")
            return False
        except Exception as e:
            print(f"[异常] 登录过程出现错误: {str(e)}")
            return False

    def get_formhash(self):
        """获取动态formhash值"""
        try:
            if self.check_signed():
                print("[提示] 今日已完成签到，无需重复操作")
                return None
                
            sign_page = self.session.get('https://bbs.binmt.cc/k_misign-sign.html')
            soup = BeautifulSoup(sign_page.text, 'html.parser')
            sign_button = soup.find('a', {'id': 'JD_sign'})
            
            if not sign_button:
                print("[错误] 找不到签到按钮")
                return None
                
            return re.search(r'formhash=([a-f0-9]+)', sign_button['href']).group(1)
        except Exception as e:
            print(f"[异常] 获取formhash失败: {str(e)}")
            return None

    def sign(self):
        """执行签到操作"""
        if self.check_signed():
            print("[提示] 签到状态检测：今日已签到")
            return True

        formhash = self.get_formhash()
        if not formhash:
            return False

        try:
            res = self.session.get(
                f'https://bbs.binmt.cc/plugin.php?id=k_misign:sign&operation=qiandao&formhash={formhash}&format=empty',
                headers={'X-Requested-With': 'XMLHttpRequest'}
            )
            
            if res.status_code == 200:
                time.sleep(1.5)  
                return self.check_signed()
            return False
        except Exception as e:
            print(f"[异常] 签到请求失败: {str(e)}")
            return False

    def get_stats(self):
        """获取签到统计数据"""
        try:
            sign_page = self.session.get('https://bbs.binmt.cc/k_misign-sign.html')
            soup = BeautifulSoup(sign_page.text, 'html.parser')
            
            return {
                '连续签到': soup.find('input', {'id': 'lxdays'})['value'],
                '签到等级': soup.find('input', {'id': 'lxlevel'})['value'],
                '积分奖励': soup.find('input', {'id': 'lxreward'})['value'],
                '总天数': soup.find('input', {'id': 'lxtdays'})['value'],
                '签到排名': soup.find('input', {'id': 'qiandaobtnnum'})['value']
            }
        except Exception as e:
            print(f"[警告] 获取统计信息失败: {str(e)}")
            return {}

    def run(self):
        """主运行流程"""
        current_date = datetime.now().strftime("%Y-%m-%d")

        if not self.login():
            print("登录失败，请检查账号密码")
            return
            
        if self.sign():
            print("\n=== 签到信息 ===")
            stats = self.get_stats()
            summary_message = (
                f"连续签到: {stats.get('连续签到', 'N/A')} 天\n"
                f"今日排名: 第{stats.get('签到排名', 'N/A')} 位\n"
                f"签到等级: Lv{stats.get('签到等级', 'N/A')}\n"
                f"本次积分: +{stats.get('积分奖励', 'N/A')}\n"
                f"总签到天数: {stats.get('总天数', 'N/A')} 天"
            )
            print(summary_message.replace('\n', '\n'))
        else:
            print("\n[提示] 签到未完成，可能已签到或出现异常")

if __name__ == '__main__':
    USERNAME = 'USERNAME'
    PASSWORD = 'PASSWORD'
    
    signer = DzSigner(USERNAME, PASSWORD)
    signer.run()
