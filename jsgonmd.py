import os
import re
import sys
import time
import signal
import queue
import sqlite3
import logging
import threading
import requests
import traceback
import urllib3
import colorama
from tqdm import tqdm
from urllib.parse import urljoin, urlparse, urlsplit, urlunsplit
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from requests.packages.urllib3.exceptions import InsecureRequestWarning

colorama.init(autoreset=True)
urllib3.disable_warnings(InsecureRequestWarning)

# --------- 配置参数 ------------
MAX_DEPTH = 2       # 最大递归深度
RETRY_TIMES = 3       # 请求失败重试次数
URLS_FILE = "url.txt"   # URL列表文件
URL_COOKIE_FILE = "url_cookie.txt"  # URL和Cookie映射文件
PATHS_FILE = "路径.txt"     # 提取到的路径文件
THIS_RUN_PATHS_FILE = "本次路径.txt"
URLS_200_FILE = "urls200out.txt"  # 成功响应的URL文件   
LOG_FILE = "scan.log"       # 日志文件
WHITELIST_FILE = "whitelist.txt"      # 白名单文件
BLACKLIST_FILE = "blacklist.txt"      # 黑名单文件
sensitive_infos_all = []  # 全局敏感信息列表


visited_urls_lock = threading.Lock()
visited_urls = set()
extracted_paths_lock = threading.Lock()
extracted_paths = set()

pause_flag = threading.Event()
exit_flag = threading.Event()
pause_flag.set()

logger = logging.getLogger("WebScanner")        
logger.setLevel(logging.INFO)
fh = logging.FileHandler(LOG_FILE, encoding='utf-8')
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
logger.addHandler(fh)

# --------- 正则表达式模式 ------------
pattern_path_raw = r'''(?:"|')( ((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']*) | ((?:/|\./|\../)[^"'><,;|()*$%\\\[\]]{1,}[^"'><,;|()*]{1,}) | ([a-zA-Z0-9_\-/.]{1,}/[a-zA-Z0-9_\-/.]+\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:\?[^"' ]*)?) | ([a-zA-Z0-9_\-/.]+\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:\?[^"' ]*)?) )(?:"|')'''
pattern_path = re.compile(pattern_path_raw, re.VERBOSE)

pattern_sensitive = re.compile(
    r'(?P<key_value>'
    r'\b(?:api_?key|oauth_?token|encrypt_?key|decrypt_?key|oauth_?secret|'
    r'(?:access|refresh|bearer)_?token|secret|ak|sk|token|auth|credential|'
    r'password|pwd|passwd|appkey|token|authentication|authorization|'
    r'accesstoken|opentoken|\u5bc6\u94a5|\u5bc6\u7801|\u79c1\u94a5|\u8d26\u53f7|\u7528\u6237\u540d|\u8ba4\u8bc1\u7801)\b'
    r'[\s=:]*'
    r'(?!\s*["\']?\s*[.)\]}/\\-])'
    r'["\']?'
    r'(?P<value>[^"\'\\/()\s-]{4,})'
    r'["\']?'
    r')'
    r'|'
    r'(?P<jwt>eyJ[a-zA-Z0-9_\-]*\.[a-zA-Z0-9_\-]*\.[a-zA-Z0-9_\-]*)',
    re.I)
    # 这个正则表达式匹配常见的敏感信息模式，包括API密钥、OAuth令牌、JWT等。
    # 其中，key_value组匹配键值对形式的敏感信息，jwt组匹配JWT令牌。
pattern_domain_ip = re.compile(
    r'(?:[a-zA-Z0-9][a-zA-Z0-9\-]{0,62}\.)+'
    r'(?:com|cn|love|hk|icu|ls|net|org|gov|edu|info|top|xyz|site|tech|me|biz|cc|co|io|tv|club|online|shop|app|dev|cloud|int|mil|arpa|arpa)'
    r'|(?:\d{1,3}\.){3}\d{1,3}'
)

EXCLUDED_EXTENSIONS = ('.css', '.ttf', '.jpg', '.jpeg', '.png', '.woff2')
DANGEROUS_ROUTES = ('delete', 'add', 'remove', 'update', 'drop')

def load_domain_filters():   #定义黑白名单
    whitelist = set()
    blacklist = set()
    if os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE, 'r', encoding='utf-8') as f:
            whitelist = {line.strip().lower() for line in f if line.strip()}
    if os.path.exists(BLACKLIST_FILE):
        with open(BLACKLIST_FILE, 'r', encoding='utf-8') as f:
            blacklist = {line.strip().lower() for line in f if line.strip()}
    return whitelist, blacklist

def load_urls_and_cookies(url_file=URLS_FILE, cookie_file=URL_COOKIE_FILE):
    url_list = []
    cookie_map = {}
    if os.path.exists(cookie_file):
        with open(cookie_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or '|||' not in line:
                    continue
                url_, cookie_ = line.split('|||', 1)
                cookie_map[url_.strip()] = cookie_.strip()
    if not os.path.exists(url_file):
        logger.error(f"{url_file} 文件不存在！程序退出。")
        sys.exit(1)
    with open(url_file, 'r', encoding='utf-8') as f:
        for line in f:
            u = line.strip()
            if u:
                url_list.append(u)
    return [(u, cookie_map.get(u, "")) for u in url_list]

def requests_retry_session(cookie="", retries=RETRY_TIMES, backoff_factor=0.3, status_forcelist=(500, 502, 504)):
    session = requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
        allowed_methods=frozenset(['GET', 'POST'])
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    if cookie:
        session.headers.update({"Cookie": cookie})
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0 Safari/537.36'
    })
    session.verify = False
    return session

def is_valid_domain_ip(domain):
    if not domain:
        return False
    if re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', domain):
        parts = domain.split('.')
        return all(0 <= int(p) <= 255 for p in parts)
    #for suffix in ('com', 'cn', 'love', 'hk', 'icu', 'ls', 'net', 'org', 'gov', 'edu', 'info', 'top', 'xyz', 'site', 'tech', 'me', 'biz', 'cc', 'co', 'io', 'tv', 'club', 'online', 'shop', 'app', 'dev', 'cloud', 'int', 'mil', 'arpa'):
    for suffix in ('com', 'cn', 'net', 'org', 'co'):   #一般
    #for suffix in ('com','com.br','com.cn','com.ph','mx','cn', 'net', 'my','me','id','org','co.id','co.th','sg','ph','vn'):     #极兔

        if domain.endswith('.' + suffix):
            return True
    return False

def clean_and_filter_paths(raw_paths):
    paths = set()
    for p in raw_paths:
        p = p.strip().strip('\'"')
        if not p:
            continue
        if '<' in p or '>' in p:
            continue
        if any(p.lower().endswith(ext) for ext in EXCLUDED_EXTENSIONS):
            continue
        paths.add(p)
    return paths

def join_url(base_url, path):
    if path.startswith('http://') or path.startswith('https://'):
        return path
    if path.startswith('//'):
        parsed = urlparse(base_url)
        return f"{parsed.scheme}:{path}"
    return urljoin(base_url, path)

def is_dangerous_path(path):
    for keyword in DANGEROUS_ROUTES:
        if keyword in path.lower():
            return True
    return False

def save_paths_to_file(paths, filepath):
    if not paths:
        return
    existing = set()
    if os.path.exists(filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                existing.add(line.strip())
    with open(filepath, 'a', encoding='utf-8') as f:
        for p in paths:
            if p not in existing:
                f.write(p + "\n")

def save_url_200(url):
    existing = set()
    if os.path.exists(URLS_200_FILE):
        with open(URLS_200_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                existing.add(line.strip())
    if url not in existing:
        with open(URLS_200_FILE, 'a', encoding='utf-8') as f:
            f.write(url + "\n")

def signal_handler(sig, frame):
    if sig == signal.SIGINT:
        print(colorama.Fore.RED + "\n用户强制终止程序，保存数据中...")
        exit_flag.set()

def input_listener():
    while not exit_flag.is_set():
        try:
            ch = sys.stdin.read(1)
            if ch.lower() == '\x0e':
                pause_flag.clear()
                print(colorama.Fore.YELLOW + "\n检测到 Ctrl+N 暂停。按 q 退出并生成报告，按 c 继续程序。")
                while True:
                    cmd = sys.stdin.read(1).lower()
                    if cmd == 'q':
                        exit_flag.set()
                        print(colorama.Fore.RED + "退出程序，生成报告中...")
                        break
                    elif cmd == 'c':
                        pause_flag.set()
                        print(colorama.Fore.GREEN + "继续执行程序。")
                        break
        except Exception:
            continue

def extract_paths_from_content(content):
    raw_paths = set()
    for m in pattern_path.finditer(content):
        for group in m.groups()[1:]:
            if group:
                raw_paths.add(group)
    return raw_paths

def extract_sensitive_info(content, source_url):
    results = []
    for m in pattern_sensitive.finditer(content):
        if m.group('key_value'):
            key_val = m.group('key_value').strip()
            parts = re.split(r'[\s=:]+', key_val, maxsplit=1)
            if len(parts) == 2:
                results.append((parts[0], parts[1], source_url))
            else:
                results.append((key_val, '', source_url))
        elif m.group('jwt'):
            results.append(('jwt', m.group('jwt'), source_url))
    return results

def extract_and_check_domains_ips(content, session):
    domains_ips = set()
    for m in pattern_domain_ip.finditer(content):
        d = m.group()
        if is_valid_domain_ip(d):
            domains_ips.add(d)
    for di in domains_ips:
        try:
            url_to_check = di
            if not di.startswith('http'):
                url_to_check = 'http://' + di
            r = session.head(url_to_check, timeout=10, allow_redirects=True)
            print(colorama.Fore.YELLOW + f"域名/IP访问: {di} 状态码: {r.status_code} 长度: {len(r.content)}")
            logger.info(f"域名/IP访问: {di} 状态码: {r.status_code} 长度: {len(r.content)}")
        except Exception as e:
            logger.warning(f"访问域名/IP异常: {di}  {e}")

def process_url(url, cookie, depth=0, whitelist=None, blacklist=None):
    if exit_flag.is_set():
        return
    
    # 白名单和黑名单判断
    parsed = urlparse(url)
    domain = parsed.hostname or ''
    domain = domain.lower()

    if whitelist and domain not in whitelist:
        logger.info(f"跳过非白名单域名: {domain}")
        return
    # if blacklist and domain in blacklist:
    if blacklist and any(domain == b or domain.endswith('.' + b) for b in blacklist):
        logger.info(f"跳过黑名单域名: {domain}")
        return

    with visited_urls_lock:
        if url in visited_urls:
            return
        visited_urls.add(url)
    pause_flag.wait()
    session = requests_retry_session(cookie=cookie)
    try:
        r = session.get(url, timeout=15)
        status_code = r.status_code
        content = r.text
        content_length = len(r.content)
        logger.info(f"访问 {url} 状态码: {status_code} 长度: {content_length}")
        print(colorama.Fore.CYAN + f"[Depth {depth}] 访问: {url} 状态码: {status_code} 长度: {content_length}")
        extract_and_check_domains_ips(content, session)
        raw_paths = extract_paths_from_content(content)
        clean_paths = clean_and_filter_paths(raw_paths)
        if clean_paths:
            print(colorama.Fore.GREEN + f"提取到路径 {len(clean_paths)} 个：")
            for p in clean_paths:
                print("  " + p)
        with extracted_paths_lock:
            new_paths = clean_paths - extracted_paths
            if new_paths:
                extracted_paths.update(new_paths)
                save_paths_to_file(new_paths, PATHS_FILE)
                save_paths_to_file(new_paths, THIS_RUN_PATHS_FILE)
        sensitive_infos = extract_sensitive_info(content,url)
        if sensitive_infos:
            print(colorama.Fore.MAGENTA + f"发现敏感信息 {len(sensitive_infos)} 条：")
            for k, v, u in sensitive_infos:
                #print(f"  {k} = {v}")
                print(f"  {k} = {v}  ({u})")
            sensitive_infos_all.extend(sensitive_infos)

        if depth >= MAX_DEPTH:
            return
        for path in clean_paths:
            if is_dangerous_path(path):
                logger.info(f"跳过危险路径 {path}")
                continue
            all_url = join_url(url, path)
            with visited_urls_lock:
                if all_url in visited_urls:
                    continue
            pause_flag.wait()
            try:
                r2 = session.get(all_url, timeout=15)
                status2 = r2.status_code
                length2 = len(r2.content)
                print(colorama.Fore.BLUE + f"访问拼接路径 {all_url} 状态码: {status2} 长度: {length2}")
                logger.info(f"访问拼接路径 {all_url} 状态码: {status2} 长度: {length2}")
                if status2 == 405:
                    r2 = session.post(all_url, timeout=15)
                    status2 = r2.status_code
                    length2 = len(r2.content)
                    print(colorama.Fore.BLUE + f"POST重试 {all_url} 状态码: {status2} 长度: {length2}")
                    logger.info(f"POST重试 {all_url} 状态码: {status2} 长度: {length2}")
                if status2 == 200:
                    save_url_200(all_url)
                    process_url(all_url, cookie, depth=depth+1, whitelist=whitelist, blacklist=blacklist)
            except Exception as e:
                logger.error(f"请求拼接路径异常 {all_url}：{e}")
    except requests.RequestException as e:
        logger.error(f"请求异常 {url}：{e}")
    except Exception as e:
        logger.error(f"处理异常 {url}：{traceback.format_exc()}")

#def generate_html_report(report_path="scan_report.html"):
def generate_html_report():
    from datetime import datetime
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    report_path = f"scan_report.{timestamp}.html"

    html = []
    html.append("<html><head><meta charset='utf-8'><title>扫描报告</title>")
    html.append("<style>")
    html.append("body { font-family: Arial; padding: 20px; background: #f5f5f5; }")
    html.append("h2 { color: #333; border-bottom: 2px solid #ccc; padding-bottom: 5px; }")
    html.append("ul { background: #fff; padding: 10px; border: 1px solid #ccc; border-radius: 5px; }")
    html.append("li { margin: 5px 0; word-break: break-all; }")
    html.append("</style></head><body>")
    html.append(f"<h1>网页扫描报告</h1>")
    html.append(f"<p>生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>")

    # 路径模块
    html.append("<h2>路径（Paths）</h2><ul>")
    if os.path.exists(PATHS_FILE):
        with open(PATHS_FILE, 'r', encoding='utf-8') as f:
            for line in sorted(set(f.readlines())):
                html.append(f"<li>{line.strip()}</li>")
    else:
        html.append("<li>暂无路径信息。</li>")
    html.append("</ul>")

    # 敏感信息模块
    html.append("<h2>敏感信息（Sensitive Info）</h2><ul>")
    if sensitive_infos_all:
        for k, v, u in sensitive_infos_all:
            html.append(f"<li><b>{k}</b>: {v}  <br><i>来源: ({u})</i></li>")
    else:
        html.append("<li>暂无敏感信息。</li>")
    html.append("</ul>")

    # 状态码200的URL
    html.append("<h2>状态码为200的URL</h2><ul>")
    if os.path.exists(URLS_200_FILE):
        with open(URLS_200_FILE, 'r', encoding='utf-8') as f:
            for line in sorted(set(f.readlines())):
                html.append(f"<li>{line.strip()}</li>")
    else:
        html.append("<li>暂无可用URL。</li>")
    html.append("</ul>")

    html.append("</body></html>")

    with open(report_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(html))
    print(colorama.Fore.GREEN + f"报告已生成：{report_path}")


def main():
    print(colorama.Fore.CYAN + "启动网页/JS提取器，读取URL并开始扫描...")
    url_cookies = load_urls_and_cookies()
    whitelist, blacklist = load_domain_filters()
    input_thread = threading.Thread(target=input_listener, daemon=True)
    input_thread.start()
    try:
        with tqdm(total=len(url_cookies), desc="扫描进度", ncols=80) as pbar:
            for url, cookie in url_cookies:
                if exit_flag.is_set():
                    break
                process_url(url, cookie, depth=0, whitelist=whitelist, blacklist=blacklist)
                pbar.update(1)
    except KeyboardInterrupt:
        exit_flag.set()
        print(colorama.Fore.RED + "\n检测到Ctrl+C，程序已退出" + colorama.Style.RESET_ALL)
    finally:
        generate_html_report()

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    main()
