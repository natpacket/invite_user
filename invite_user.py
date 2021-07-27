# -*- coding:utf-8 -*-

import requests
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.PublicKey import RSA
import base64
import random


# 把原账号绑定微信 以防丢失
# 1. qq先登录 绑定手机
# 2. 解绑qq，重新用手机登录
# 3. 填写邀请码，并且注销账号
# 4. 反复循环前三步

# 随机名字
def rand_name():
    name = '通友{}'
    return name.format(random.randint(122268, 180000))


def ras_encrypt(plain, public_key):
    rsakey = RSA.importKey(str(public_key))
    cipher = Cipher_pkcs1_v1_5.new(rsakey)
    cipher_text = base64.b64encode(cipher.encrypt(bytes(plain.encode("utf8"))))
    return str(cipher_text, 'utf-8')


# qq登录
def qq_login(login_key):
    PUBLIC_KEY_TOKEN = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCNkKNoYNo3WC6wEvZIXoW00GRuYiI9o6osjtXd79VnKuPnbcTfSQi+Gg2dSYWpkNqs90c3+tQ6yyM/U0HkWo1B5eTVeJw18tcygRryOgrsqLnaTOGsLAgJ2rV8mhRfpRNtVR+b18GrddSPmVXOYPMpXXGP0Cz5GhZBu6nQ+eB7ZwIDAQAB";
    pub_key = f'-----BEGIN PUBLIC KEY-----\n{PUBLIC_KEY_TOKEN}\n-----END PUBLIC KEY-----'
    text = "userid={}&platform=4&dev=iphone"
    ciphertext = ras_encrypt(text, pub_key)
    headers = {
        'Host': 'news.cninct.com',
        'Content-Type': 'application/json',
        'Token-Cninct': f'{ciphertext}',
        'User-Agent': 'Build/5.5.3 (com.suitang.jjt; build:2; iOS 14.2.0) Alamofire/5.0.2',
    }
    data = {"device_token": "de3ba5f58db223dd02b590337721f142dbe3ada7d5f2016186afbf699fd4bdbe", "self_login_pwd": "",
            "self_login_type": 3, "login_key": login_key, "self_login_nick_name": rand_name(),
            "self_login_pic_url": ""}
    res = requests.post(url='https://news.cninct.com/JiJianTong?op=SelfLogin', headers=headers, json=data)
    result = res.json().get('ext').get('result')[0]
    userid = result.get('userid')
    account_id = result.get('account_id')
    # print(userid)
    print("qq登录状态：" + res.text)
    token = ras_encrypt(text.format(userid), pub_key)
    # print(token)
    return token, account_id


# 获取验证码
def get_sms_code():
    headers = {
        'Host': 'news.cninct.com',
        'Content-Type': 'application/json',
        'User-Agent': 'Build/5.5.3 (com.suitang.jjt; build:2; iOS 14.2.0) Alamofire/5.0.2',
    }
    data = {"account": "18483618398"}
    res = requests.post(url='https://news.cninct.com/JiJianTong?op=GetLoginSmsCode', headers=headers, json=data)
    print("验证码获取状态：" + res.text)


# 解绑qq
def unbind_qq(token):
    headers = {
        'Host': 'news.cninct.com',
        'Content-Type': 'application/json',
        'User-Agent': 'Build/5.5.3 (com.suitang.jjt; build:2; iOS 14.2.0) Alamofire/5.0.2',
        'Token-Cninct': f'{token}',
    }
    data = {"self_login_type": 3}
    res = requests.post(url='https://news.cninct.com/JiJianTong?op=UntieAccountLoginKey', headers=headers, json=data)
    print("解绑qq号状态：" + res.text)


# 微信登录
def login_wx(login_key):
    PUBLIC_KEY_TOKEN = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCNkKNoYNo3WC6wEvZIXoW00GRuYiI9o6osjtXd79VnKuPnbcTfSQi+Gg2dSYWpkNqs90c3+tQ6yyM/U0HkWo1B5eTVeJw18tcygRryOgrsqLnaTOGsLAgJ2rV8mhRfpRNtVR+b18GrddSPmVXOYPMpXXGP0Cz5GhZBu6nQ+eB7ZwIDAQAB";
    pub_key = f'-----BEGIN PUBLIC KEY-----\n{PUBLIC_KEY_TOKEN}\n-----END PUBLIC KEY-----'
    text = "userid={}&platform=4&dev=iphone"
    ciphertext = ras_encrypt(text, pub_key)
    headers = {
        'Host': 'news.cninct.com',
        'Content-Type': 'application/json',
        'Token-Cninct': f'{ciphertext}',
        'User-Agent': 'Build/5.5.3 (com.suitang.jjt; build:2; iOS 14.2.0) Alamofire/5.0.2',
    }
    data = {"device_token": "de3ba5f58db223dd02b590337721f142dbe3ada7d5f2016186afbf699fd4bdbe", "self_login_pwd": "",
            "self_login_type": 2, "login_key": login_key, "self_login_nick_name": "通友68858",
            "self_login_pic_url": ""}
    res = requests.post(url='https://news.cninct.com/JiJianTong?op=SelfLogin', headers=headers, json=data)
    result = res.json().get('ext').get('result')[0]
    userid = result.get('userid')
    account_id = result.get('account_id')
    # print(userid)
    print("微信登录状态：" + res.text)
    token = ras_encrypt(text.format(userid), pub_key)
    # print(token)
    return token, account_id


# 绑定微信
def bind_wx(token, login_key):
    data = {"self_login_type": 2, "login_key": login_key}
    headers = {
        'Host': 'news.cninct.com',
        'Content-Type': 'application/json',
        'User-Agent': 'Build/5.5.3 (com.suitang.jjt; build:2; iOS 14.2.0) Alamofire/5.0.2',
        'Token-Cninct': f'{token}',
    }
    res = requests.post(url=' https://news.cninct.com/JiJianTong?op=BindAccountLoginKey', headers=headers, json=data)
    print("微信绑定状态：" + res.text)


# 填写邀请码
def write_code(token, code):
    data = {"friend_account_id_un": int(code)}
    headers = {
        'Host': 'news.cninct.com',
        'Content-Type': 'application/json',
        'User-Agent': 'Build/5.5.3 (com.suitang.jjt; build:2; iOS 14.2.0) Alamofire/5.0.2',
        'Token-Cninct': f'{token}',
    }
    resp = requests.post(url='https://news.cninct.com/JiJianTong?op=UploadVipFrientCode', json=data, headers=headers)
    print("邀请结果：" + resp.text)


# 永久注销
def permanent_logOff(account_id, token):
    data = {"account_id": account_id}
    headers = {
        'Host': 'news.cninct.com',
        'Content-Type': 'application/json',
        'User-Agent': 'Build/5.5.3 (com.suitang.jjt; build:2; iOS 14.2.0) Alamofire/5.0.2',
        'Token-Cninct': f'{token}',
    }
    res = requests.post(url='https://news.cninct.com/JiJianTong?op=PermanentLogOff', json=data, headers=headers)
    print("注销状态：" + res.text)


if __name__ == '__main__':
    code = input('请输入邀请码：')
    wx_login_key = input('请输入微信key：')  # 任意28位即可
    qq_login_key = input('请输入qq key：')  # 任意32位即可
    token, account_id = qq_login(qq_login_key)
    # 绑定微信
    bind_wx(token, wx_login_key)
    # 解绑qq
    unbind_qq(token)
    # 微信重新登录
    token, account_id = login_wx(wx_login_key)
    write_code(token, code)
    permanent_logOff(account_id, token)
