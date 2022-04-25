import json, time, threading, base64, httpx, itertools, imap_tools, re, os, random, keyboard, websocket, sys, multiprocessing, ctypes
from psutil import process_iter, NoSuchProcess, AccessDenied, ZombieProcess
from colorama import Fore, init; init()
from AuthGG.client import Client
from typing import Tuple

lock = threading.Lock()
config = json.load(open('../script/config.json'))
avatars = itertools.cycle(os.listdir('../data/avatar/'))
proxies = itertools.cycle(open('../data/proxies.txt', 'r').readlines())
static_proxies = itertools.cycle(open('../data/static_proxies.txt', 'r').readlines())
usernames = itertools.cycle(open('../data/usernames.txt', 'r', errors='ignore', encoding='utf-8').readlines())


class AntiDebug(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def detect_vm(self):
        if hasattr(sys, 'real_prefix'):
            sys.exit(0)

    def detect_hdd(self):
        from ctypes import c_ulonglong, windll, byref

        free_bytes_available = c_ulonglong()
        total_number_of_bytes = c_ulonglong()
        total_number_of_free_bytes = c_ulonglong()

        windll.kernel32.GetDiskFreeSpaceExA(
            'C:',
            byref(free_bytes_available),
            byref(total_number_of_bytes),
            byref(total_number_of_free_bytes)
        )

        total_number_of_gigabytes = total_number_of_bytes.value / (1024 ** 3)
        disk_space = 0

        if disk_space < 100:
            sys.exit(0)

    def detect_core(self):
        if multiprocessing.cpu_count() == 1:
            sys.exit(0)

    def check_for_process(self):
        for proc in process_iter():
            try:
                for name in ['regmon', 'diskmon', 'procmon', 'http', 'traffic', 'wireshark', 'fiddler', 'packet',
                             'debugger', 'debuger', 'dbg', 'ida', 'dumper', 'pestudio', 'hacker', "vboxservice.exe",
                             "vboxtray.exe",
                             "vmtoolsd.exe",
                             "vmwaretray.exe",
                             "vmwareuser",
                             "VGAuthService.exe",
                             "vmacthlp.exe",
                             "vmsrvc.exe",
                             "vmusrvc.exe",
                             "prl_cc.exe",
                             "prl_tools.exe",
                             "xenservice.exe",
                             "qemu-ga.exe",
                             "joeboxcontrol.exe",
                             "joeboxserver.exe",
                             "joeboxserver.exe"]:
                    if name.lower() in proc.name().lower():
                        try:
                            proc.kill()
                        except:
                            sys.exit(0)
            except (NoSuchProcess, AccessDenied, ZombieProcess):
                pass

    def check_for_debugger(self):
        if ctypes.windll.kernel32.IsDebuggerPresent() != 0 or ctypes.windll.kernel32.CheckRemoteDebuggerPresent(
                ctypes.windll.kernel32.GetCurrentProcess(), False) != 0:
            sys.exit()

    def detect_screen_syze(self):
        x = ctypes.windll.user32.GetSystemMetrics(0)
        y = ctypes.windll.user32.GetSystemMetrics(1)

        if x <= 200 or y <= 200:
            sys.exit()

    def run(self):
        self.detect_screen_syze()
        self.detect_core()
        self.detect_hdd()
        self.detect_vm()

        while True:
            self.check_for_process()
            self.check_for_debugger()
            time.sleep(3)


class Console:
    _generated, _verified, _locked, _proxy_err, _cap_worker, _mail_worker = 0, 0, 0, 0, 0, 0

    @staticmethod
    def debug(content: str):
        if config['debug']:
            lock.acquire()
            print(f'{Fore.LIGHTMAGENTA_EX}[DEBUG] {content}{Fore.RESET}')
            lock.release()

    @staticmethod
    def printf(content: str):
        lock.acquire()
        print(content.replace('[+]', f'[{Fore.LIGHTGREEN_EX}+{Fore.RESET}]').replace('[*]',
                                                                                     f'[{Fore.LIGHTYELLOW_EX}*{Fore.RESET}]').replace(
            '[>]', f'[{Fore.CYAN}>{Fore.RESET}]').replace('[-]', f'[{Fore.RED}-{Fore.RESET}]'))
        lock.release()

    @staticmethod
    def title_thread():
        start_time = time.time()

        while True:
            time.sleep(1)
            work_token_min = round(Console._generated / ((time.time() - start_time) / 60))
            all_token_min = round(Console._generated + Console._locked / ((time.time() - start_time) / 60))
            os.system(
                f'title [0xGen - 0xVichy#1234 - Private] Generated: {Console._generated} - Verified: {Console._verified} - Locked: {Console._locked} - ProxyErr: {Console._proxy_err} | Workers: [Captcha: {Console._cap_worker} Verification: {Console._mail_worker} Total: {config["threads"]}] | W.T/M: {work_token_min} - Ttl.T/M: {all_token_min} | Debug: {config["debug"]}'.replace(
                    '|', '^|'))

    @staticmethod
    def key_bind_thread():
        while True:
            time.sleep(0.2)
            if keyboard.is_pressed('up'):
                config['threads'] += 1

            if keyboard.is_pressed('down'):
                config['threads'] -= 1

            if keyboard.is_pressed('left'):
                config['debug'] = True

            if keyboard.is_pressed('right'):
                config['debug'] = False

            if config['threads'] < 0:
                config['threads'] = 0

    @staticmethod
    def print_logo():
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f'''      
   ██████╗ ██╗  ██╗ ██████╗ ███████╗███╗   ██╗ {Fore.LIGHTWHITE_EX}Made by  github.com/its-vichy | t.me/Its_Vichy.{Fore.LIGHTRED_EX}
  ██╔═████╗╚██╗██╔╝██╔════╝ ██╔════╝████╗  ██║ {Fore.LIGHTWHITE_EX}Discord: discord.gg/terms-of-service.{Fore.LIGHTRED_EX}
  ██║██╔██║ ╚███╔╝ ██║  ███╗█████╗  ██╔██╗ ██║ {Fore.LIGHTWHITE_EX}Support: t.me/OxTokens.{Fore.LIGHTRED_EX}
  ████╔╝██║ ██╔██╗ ██║   ██║██╔══╝  ██║╚██╗██║ {Fore.LIGHTWHITE_EX}V0.1{Fore.LIGHTRED_EX}
  ╚██████╔╝██╔╝ ██╗╚██████╔╝███████╗██║ ╚████║
   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝{Fore.LIGHTWHITE_EX}
        '''.replace('█', f'{Fore.LIGHTWHITE_EX}█{Fore.LIGHTRED_EX}'))


class CaptchaSolver:
    @staticmethod
    def get_captcha_key_by_hand() -> str:
        return input('Captcha-key: ')

    @staticmethod
    def get_captcha_key(static_proxy: str, proxy: str, site_key: str = '4c672d35-0701-42b2-88c3-78380b0db560') -> str:
        Console._cap_worker += 1

        task_payload = {
            'clientKey': config['captcha_key'],
            'task': {
                'userAgent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) discord/1.0.1012 Chrome/91.0.4472.164 Electron/13.6.6 Safari/537.36',
                'websiteKey': site_key,
                'websiteURL': 'https://ptb.discord.com',
                'type': 'HCaptchaTask',

                'proxyPassword': static_proxy.split('@')[0].split(':')[1],
                'proxyAddress': static_proxy.split('@')[1].split(':')[0],
                'proxyLogin': static_proxy.split('@')[0].split(':')[0],
                'proxyPort': static_proxy.split('@')[1].split(':')[1],
                'proxyType': 'http',
            }
        }
        key = None

        with httpx.Client(proxies=f'http://{proxy}',
                          headers={'content-type': 'application/json', 'accept': 'application/json'},
                          timeout=30) as client:
            try:
                task_id = client.post(f'https://api.{config["captcha_api"]}/createTask', json=task_payload).json()[
                    'taskId']
                Console.debug(f'Recieved captcha task ID: {task_id}')

                get_task_payload = {
                    'clientKey': config['captcha_key'],
                    'taskId': task_id
                }

                while key is None:
                    try:
                        response = client.post(f'https://api.{config["captcha_api"]}/getTaskResult',
                                               json=get_task_payload,
                                               timeout=30).json()
                        Console.debug(f'Recieved captcha task response: {response}')

                        if 'ERROR_PROXY_CONNECT_REFUSED' in str(response):
                            Console._proxy_err += 1
                            Console._cap_worker -= 1
                            return 'ERROR'

                        if 'ERROR' in str(response):
                            Console._cap_worker -= 1
                            return 'ERROR'

                        if response['status'] == 'ready':
                            key = response['solution']['gRecaptchaResponse']
                        else:
                            time.sleep(3)
                    except Exception as e:
                        Console.debug(f'Captcha task result error: {e}')

                        if 'ERROR_PROXY_CONNECT_REFUSED' in str(e):
                            Console._proxy_err += 1
                            key = 'ERROR'
                        else:
                            pass

                Console._cap_worker -= 1
                return key

            except Exception as e:
                Console.debug(f'Captcha task result error: {e}')

                if 'ERROR_PROXY_CONNECT_REFUSED' in str(e):
                    Console._proxy_err += 1
                    Console._cap_worker -= 1
                    return 'ERROR'
                else:
                    pass


class DiscordApi:
    @staticmethod
    def get_super_properties(encoded: bool = True) -> [str, dict]:
        payload = {
            "os": "Windows",
            "browser": "Discord Client",
            "release_channel": "ptb",
            "client_version": "1.0.1012",
            "os_version": "10.0.19042",
            "os_arch": "x64",
            "system_locale": "fr",
            "client_build_number": 113977,
            "client_event_source": None
        }

        return base64.b64encode(json.dumps(payload, separators=(',', ':')).encode()).decode() if encoded else payload

    @staticmethod
    def get_xtrack(encoded: bool = True) -> [str, dict]:
        payload = {
            "os": "Windows",
            "browser": "Discord Client",
            "release_channel": "ptb",
            "client_version": "1.0.1012",
            "os_version": "10.0.19042",
            "os_arch": "x64",
            "system_locale": "fr",
            "client_build_number": 113977,
            "client_event_source": None
        }

        return base64.b64encode(json.dumps(payload, separators=(',', ':')).encode()).decode() if encoded else payload

    @staticmethod
    def get_cookies_fingerprint(proxy: str) -> [httpx.Cookies, str]:
        while True:
            try:
                response = httpx.get('https://ptb.discordapp.com/api/v9/experiments', proxies=proxy, timeout=30)

                # __cf_bm = cookie_bypass.CookieBypass().generate_cookie()

                cookies = httpx.Cookies()
                cookies.set('__sdcfduid', response.cookies.get('__sdcfduid'), domain='ptb.discord.com')
                cookies.set('__dcfduid', response.cookies.get('__dcfduid'), domain='ptb.discord.com')
                # cookies.set('__stripe_mid', '2e0bcaf6-01bd-4f02-bb30-76cb5c5946824671af;', domain='.ptb.discord.com')
                # cookies.set('__cf_bm', 'avh33b1fsxeIIYKATXoSDKWg_TR3KBI5oHAAI7lCkek-1644107105-0-AXSlfWwOnBQCxcSP2XXwClL88ZG8fxYd8S7clofNHSzcLH4TJf/QsIqMO1i7tqyTfNHe+5GhRuYaVYXXGt/EDoXDn11zXGXcDyTUuSPhy/HWgBK3N1ErLpSRpKiFWI87fA==',domain='.discord.com')
                # cookies.set('__cf_bm', __cf_bm, domain='.discord.com')
                # cookies.set('locale', 'fr', domain='discord.com')

                return cookies, response.json()['fingerprint']
            except Exception as e:
                Console.debug(f'Get fingerprint error: {e}')

    @staticmethod
    def check_flag(token: str):
        flag_list = {
            0: 'User is not flagged',
            1048576: 'User is marked as a spammer.',
            2199023255552: 'User is currently temporarily or permanently disabled.'
        }

        response = httpx.get('https://discord.com/api/v9/users/@me',
                             headers={'authorization': token, 'content-type': 'application/json'}, timeout=30).json()

        for flag_id, flag_text in flag_list.items():
            if response['flags'] == flag_id or response['public_flags'] == flag_id:
                Console.debug(f'Flag found: "{flag_text}" on {token}')

    @staticmethod  # The function lock the tokens ?
    def is_locked_account(token: str) -> bool:
        proxy = next(proxies).split('\n')[0]
        headers = {
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) discord/1.0.1012 Chrome/91.0.4472.164 Electron/13.6.6 Safari/537.36',
            'content-type': 'application/json',
        }

        with httpx.Client(proxies=f'http://{proxy}', headers=headers, timeout=30) as client:
            status_code = client.get('https://discord.com/api/v9/users/@me/library').status_code

            if status_code == 200:
                return False
            else:
                return True


class DiscordWs(threading.Thread):
    def __init__(self, acc_token: str) -> None:
        self.token = acc_token
        self.running = True
        self.ws = websocket.WebSocket()
        threading.Thread.__init__(self)

    def send_payload(self, payload: dict) -> None:
        self.ws.send(json.dumps(payload))

    def recieve(self) -> dict:
        data = self.ws.recv()

        if data:
            return json.loads(data)

    def heartbeat(self, interval: float):
        while self.running:
            time.sleep(interval)
            self.send_payload({
                'op': 1,
                'd': None
            })
            Console.debug(f'Heartbeat sent: {self.token}')

    def login(self):
        self.ws.connect('wss://gateway.discord.gg/?encoding=json')
        interval = self.recieve()['d']['heartbeat_interval'] / 1000
        threading.Thread(target=self.heartbeat, args=(interval,)).start()

    def online(self):
        self.send_payload({
            "op": 2,
            "d": {
                "token": self.token,
                "capabilities": 253,
                "properties": DiscordApi.get_super_properties(False),
                "presence": {
                    "status": "online",
                    "since": 0,
                    "activities": [],
                    "afk": False
                },
                "compress": False,
                "client_state": {
                    "guild_hashes": {},
                    "highest_last_message_id": "0",
                    "read_state_version": 0,
                    "user_guild_settings_version": -1,
                    "user_settings_version": -1
                }
            }
        })

        time.sleep(6)

        self.send_payload({
            "op": 3,
            "d": {
                "status": "idle",
                "since": 0,
                "activities": [
                    {
                        "name": "Custom Status",
                        "type": 4,
                        "state": "0xGen on the top",
                        "emoji": None
                    }
                ],
                "afk": False
            }
        })

    def run(self):
        self.login()
        self.online()
        time.sleep(30)
        self.running = False


# todo: get client and just update payload & headers
class RequestBuilder:
    @staticmethod
    def calculate_content_lenght(payload: dict) -> str:
        return str(len(json.dumps(payload)))

    @staticmethod
    def get_register(cookies, fingerprint: str, username: str) -> [httpx.Client, dict]:
        proxy = next(proxies).split('\n')[0]
        static_proxy = next(static_proxies).split('\n')[0]
        captcha_key = CaptchaSolver.get_captcha_key_by_hand() if config['captcha_by_hand'] == True else CaptchaSolver.get_captcha_key(static_proxy, proxy)

        if captcha_key == 'ERROR':
            return None, None

        payload = {
            'captcha_key': captcha_key,
            'fingerprint': fingerprint,
            'username': username,
            'consent': True,
        }

        http_client = httpx.Client(proxies= None if config['captcha_by_hand'] == True else f'http://{static_proxy}', timeout=30)
        http_client.cookies = cookies
        http_client.headers = {
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) discord/1.0.1012 Chrome/91.0.4472.164 Electron/13.6.6 Safari/537.36',
            'sec-ch-ua': '" Not;A Brand";v="99", "Google Chrome";v="97", "Chromium";v="97"',
            'accept-language': 'fr,fr-FR;q=0.9',
            'accept-encoding': 'gzip, deflate, br',
            'content-type': 'application/json',
            'sec-ch-ua-platform': '"Windows"',
            'referer': 'https://ptb.discord.com/register',
            'origin': 'https://ptb.discord.com',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-ch-ua-mobile': '?0',
            'accept': '*/*',

            'cookie': f'__dcfduid={cookies.get("__dcfduid")}; __sdcfduid={cookies.get("__sdcfduid")}; locale=fr',
            'content-length': RequestBuilder.calculate_content_lenght(payload),
            'x-super-properties': DiscordApi.get_super_properties(),
            'x-fingerprint': fingerprint,

            'x-debug-options': 'bugReporterEnabled',
            'x-discord-locale': 'fr',
        }

        return http_client, payload

    @staticmethod
    def get_verifier(cookies, fingerprint: str, token: str, email: str, password: str) -> [httpx.Client, dict]:
        proxy = next(proxies).split('\n')[0]

        payload = {
            'email': email,
            'password': password,
            'date_of_birth': '1998-01-05',
            'bio': f"*{httpx.get('https://free-quotes-api.herokuapp.com', proxies=f'http://{proxy}', timeout=30).json()['quote']}*",
            'avatar': f"data:image/png;base64,{base64.b64encode(open(f'../data/avatar/{next(avatars)}', 'rb').read()).decode()}",
        }

        http_client = httpx.Client(proxies=f'http://{proxy}', timeout=30)
        http_client.cookies = cookies
        http_client.headers = {
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) discord/1.0.1012 Chrome/91.0.4472.164 Electron/13.6.6 Safari/537.36',
            'sec-ch-ua': '" Not;A Brand";v="99", "Google Chrome";v="97", "Chromium";v="97"',
            'accept-language': 'fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7',
            'accept-encoding': 'gzip, deflate, br',
            'content-type': 'application/json',
            'sec-ch-ua-platform': '"Windows"',
            'referer': 'https://ptb.discord.com/channels/@me',
            'origin': 'https://ptb.discord.com',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-ch-ua-mobile': '?0',
            'accept': '*/*',

            'cookie': f'__dcfduid={cookies.get("__dcfduid")}; __sdcfduid={cookies.get("__sdcfduid")};',
            # ; locale=fr; __cf_bm={cookies.get("__cf_bm")}
            'content-length': RequestBuilder.calculate_content_lenght(payload),
            'x-track': DiscordApi.get_xtrack(),
            'x-fingerprint': fingerprint,

            'x-debug-options': 'bugReporterEnabled',
            'x-discord-locale': 'fr',
            'authorization': token,
        }

        return http_client, payload

    @staticmethod
    def get_sms(cookies, fingerprint: str, token: str) -> httpx.Client:
        proxy = next(proxies).split('\n')[0]

        http_client = httpx.Client(proxies=f'http://{proxy}', timeout=30)
        http_client.cookies = cookies
        http_client.headers = {
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) discord/1.0.1012 Chrome/91.0.4472.164 Electron/13.6.6 Safari/537.36',
            'sec-ch-ua': '" Not;A Brand";v="99", "Google Chrome";v="97", "Chromium";v="97"',
            'accept-language': 'fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7',
            'accept-encoding': 'gzip, deflate, br',
            'content-type': 'application/json',
            'sec-ch-ua-platform': '"Windows"',
            'referer': 'https://ptb.discord.com/channels/@me',
            'origin': 'https://ptb.discord.com',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-ch-ua-mobile': '?0',
            'accept': '*/*',

            'cookie': f'__dcfduid={cookies.get("__dcfduid")}; __sdcfduid={cookies.get("__sdcfduid")};',
            # ; locale=fr; __cf_bm={cookies.get("__cf_bm")}
            'x-super-properties': DiscordApi.get_super_properties(),
            'x-fingerprint': fingerprint,

            'x-debug-options': 'bugReporterEnabled',
            'x-discord-locale': 'fr',
            'authorization': token,
        }

        return http_client


class HotmailboxServiceClient:
    @staticmethod
    def get_mail_pass() -> Tuple[str, str]:
        while True:
            try:
                proxy = next(proxies).split('\n')[0]

                with httpx.Client(proxies=f'http://{proxy}', timeout=30) as client:
                    stock = client.get('https://api.hotmailbox.me/mail/currentstock').json()['Data']
                    mail_code = None

                    for data in stock:
                        if data['Instock'] > 1:
                            mail_code = data['MailCode']

                    email = client.get(
                        f'https://api.hotmailbox.me/mail/buy?apikey={config["email_key"]}&mailcode={mail_code}&quantity=1').json()

                    return email['Data']['Emails'][0]['Email'], email['Data']['Emails'][0]['Password']
            except Exception as e:
                Console.debug(f'Get mail error: {e}')
                pass

    @staticmethod
    def get_verification_token(email: str, password: str) -> str:
        Console._mail_worker += 1
        while True:
            try:
                with imap_tools.MailBox('pop-mail.outlook.com', '993').login(email, password, 'INBOX') as mailbox:
                    for msg in mailbox.fetch():
                        if msg.to[0] == email and msg.from_ == 'noreply@discord.com':
                            body = msg.html
                            for url in re.findall(
                                    r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
                                    body):
                                redirect = None
                                while redirect is None:
                                    try:
                                        redirect = httpx.get(url, follow_redirects=True, timeout=30).url
                                    except Exception as e:
                                        print(f'redirect err: {e}')
                                        pass

                                if 'https://discord.com/verify#token=' in str(redirect):
                                    Console._mail_worker -= 1
                                    return str(redirect).split('https://discord.com/verify#token=')[1]
            except Exception as e:
                Console.debug(f'Mail verification error: {e}')
                time.sleep(3)
                pass


class KopeechkaServiceClient:
    def checkEmail(self):
        response = httpx.get(
            'https://api.kopeechka.store/mailbox-get-message?full=1&spa=1&id=' + self.id + '&token=' + config[
                'email_key']).json()
        return response['value']

    def deleteEmail(self):
        httpx.get('https://api.kopeechka.store/mailbox-cancel?id=' + self.id + '&token=' + config['email_key'])

    def get_verification_token(self):
        tries = 0
        while tries < 35:
            time.sleep(2)
            value = self.checkEmail()
            if value != 'WAIT_LINK':
                try:
                    return str(httpx.get(value.replace('\\', ''), follow_redirects=True, timeout=30).url).split('https://discord.com/verify#token=')[1]
                    self.deleteEmail()
                except:
                    pass
            tries += 1
        return False

    def __init__(self):
        response = httpx.get(
            'https://api.kopeechka.store/mailbox-get-email?api=2.0&spa=1&site=discord.com&sender=discord&regex=&mail_type=REAL&token=' +
            config['email_key']).json()
        if response['status'] == 'OK':
            self.id = response['id']
            self.email = response['mail']
        else:
            Exception(response)


class PhoneApi:
    @staticmethod
    def get_phone_number() -> Tuple[str, str]:
        err = 0
        bl = []
        while True:
            base_url = f'https://api.sms-activate.org/stubs/handler_api.php?api_key={config["phone_key"]}'
            with httpx.Client() as client:
                prices = client.get(f'{base_url}&action=getPrices&service=ds').json()

                country_code = 3
                cheap_cost = 100
                for price in prices:
                    if 'ds' not in str(prices[price]):
                        continue

                    item = prices[price]['ds']

                    if item['count'] == 0:
                        continue

                    if cheap_cost > item['cost'] and price not in bl:
                        cheap_cost = item['cost']
                        country_code = price

                Console.debug(f'Best country for phone found -> country: {country_code} --> price:  {cheap_cost}')

                response = client.get(f'{base_url}&action=getNumber&service=ds&country={country_code}').text.split(':')

                if response == [''] or response == ['NO_NUMBERS']:
                    if err == 3:
                        Console.debug(f'Blacklist country {country_code} due to many errors.')
                        bl.append(country_code)
                    else:
                        err += 1

                    Console.debug('Unable to get phone number, sleep 1s')
                    time.sleep(1)
                    continue

                #      task-id      phone-numb
                return response[1], response[2]

    @staticmethod
    def get_verification_code(task_id: str) -> [str, None]:
        base_url = f'https://api.sms-activate.org/stubs/handler_api.php?api_key={config["phone_key"]}'
        with httpx.Client() as client:
            Console.debug(client.get(f'{base_url}&action=setStatus&status=1&id={task_id}').text)

            errors = 0
            while errors < 60:
                response = client.get(f'{base_url}&action=getStatus&id={task_id}').text
                Console.debug(response)
                if 'STATUS_OK' in response:
                    return response.split(':')[1]
                else:
                    Console.debug(f'wait phone: {errors}')
                    time.sleep(1)
                    errors += 1

            Console.debug('banned phone / sms never sent')
            Console.debug(client.get(f'{base_url}&action=setStatus&status=8&id={task_id}').text)
            return None


class CreatorWorker(threading.Thread):
    def __init__(self) -> None:
        self.request_builder = RequestBuilder()
        self.cookies, self.fingerprint = DiscordApi.get_cookies_fingerprint('http://' + next(proxies).split("\n")[0])
        threading.Thread.__init__(self)

    def register(self, username: str) -> [str, None]:
        try:
            session, payload = self.request_builder.get_register(self.cookies, self.fingerprint, username)

            if session is None:
                Console.debug('Session is none')

            response = session.post('https://ptb.discord.com/api/v9/auth/register', json=payload).json()

            if 'token' in str(response):
                token = response['token']

                session.headers['x-debug-options'] = 'bugReporterEnabled'
                session.headers['authorization'] = token
                session.headers['x-discord-locale'] = 'fr'
                session.headers.pop('content-length')

                if 'x-track' in str(session.headers):
                    session.headers.pop('x-track')

                session.headers['referer'] = 'https://ptb.discord.com/channels/@me'
                rep = httpx.get('https://ptb.discord.com/api/v9/users/@me/affinities/users', headers=session.headers, cookies=session.cookies)

                """if DiscordApi.is_locked_account(token):
                    Console.printf(f'[-] Locked token: {token}')
                    return None
                else:
                    Console.printf(f'[+] Unlocked token: {token}')
                    DiscordApi.check_flag(token)
                """
                if rep.status_code == 403:
                    Console.printf(f'[-] Locked token: {token}')
                    Console._locked += 1
                    return None
                else:
                    Console.printf(f'[+] Unlocked token: {token}')
                    Console._generated += 1
                    return token
            else:
                print(response)
                return None
        except Exception as e:
            Console.debug(f'Creation error: {e}')
            return None

    def verifier(self, token: str) -> [Tuple[str, str, str], None]:
        email, password, tmp, verification_token = None, None, None, None

        if config['email_api'] == 'hotmailbox':
            email, password = HotmailboxServiceClient.get_mail_pass()
        elif config['email_api'] == 'kopeechka':
            tmp = KopeechkaServiceClient()
            email = tmp.email
            password = '!!0xGen%%1337'

        session, payload = self.request_builder.get_verifier(self.cookies, self.fingerprint, token, email, password)
        Console.debug(f'Got email/pass/payload/session: {email}:{password}')

        response = session.patch('https://ptb.discord.com/api/v9/users/@me', json=payload).json()

        if 'token' in str(response):
            token = response['token']
            session.headers['authorization'] = token
            hypesquad_payload = {'house_id': random.randint(1, 3)}
            session.headers['content-length'] = self.request_builder.calculate_content_lenght(hypesquad_payload)
            session.post('https://ptb.discord.com/api/v9/hypesquad/online', json=hypesquad_payload)

            if config['email_api'] == 'hotmailbox':
                verification_token = HotmailboxServiceClient.get_verification_token(email, password)
            elif config['email_api'] == 'kopeechka':
                verification_token = tmp.get_verification_token()

            need_captcha = False
            while True:
                # add content lenght
                session.headers.pop('content-length')
                resp = session.post('https://ptb.discord.com/api/v9/auth/verify', json={
                    'captcha_key': None if need_captcha == False else CaptchaSolver.get_captcha_key(
                        f'http://{next(proxies)}', next(static_proxies)), 'token': verification_token}).json()

                try:
                    if 'captcha' in str(resp):
                        need_captcha = True
                        print('need captcha')
                    elif 'token' in str(response):
                        Console._verified += 1
                        return resp['token'], email, password
                    else:
                        print(response)
                        return None, None, None
                except:
                    return None, None, None
        else:
            print(response)
            return None, None, None

    def phone_verifier(self, token: str, password: str) -> str:
        http_client = self.request_builder.get_sms(self.cookies, self.fingerprint, token)
        task_id, phone_num = PhoneApi.get_phone_number()

        submit_phone_payload = {'phone': f'+{phone_num}', 'change_phone_reason': 'user_settings_update',
                                'captcha_key': CaptchaSolver.get_captcha_key(next(static_proxies).split('\n')[0],
                                                                             next(proxies).split('\n')[0],
                                                                             'f5561ba9-8f1e-40ca-9b5b-a0b3f719ef34')}
        r = http_client.post('https://discord.com/api/v9/users/@me/phone', json=submit_phone_payload)

        if r.status_code == 400:
            Console.debug(f'Error 400 when submit phone: {r.text}')
            return None
        else:
            Console.debug(f'Phone submited')

        code = PhoneApi.get_verification_code(task_id)
        Console.debug(f'Verification code found: {code}')

        submit_code_paylaod = {'phone': f'+{phone_num}', 'code': code}
        http_client.headers['content-lenght'] = self.request_builder.calculate_content_lenght(submit_code_paylaod)
        verif_token = http_client.post('https://ptb.discord.com/api/v9/phone-verifications/verify',
                                       json=submit_code_paylaod).json()

        submit_verif_token_payload = {'phone_token': verif_token, 'password': password,
                                      'change_phone_reason': 'user_settings_update'}
        http_client.headers['content-lenght'] = self.request_builder.calculate_content_lenght(submit_verif_token_payload)
        response_code = http_client.post('https://ptb.discord.com/api/v9/users/@me/phone',
                                         json=submit_verif_token_payload).status_code

    def run(self) -> None:
        token = self.register(next(usernames))

        if token is None:
            Console.debug(f'Error when creating account, no token was returned')
            return

        if config['verify_mail'] == True:
            token, email, password = self.verifier(token)
            Console.printf(f'[+] Mail verified: {token}')

            if config['verify_phone'] == True:
                token = self.phone_verifier(token, password)
                Console.printf(f'[+] Phone verified: {token}')

            DiscordWs(token).start()

            with open('../data/tokens.txt', 'a+') as token_file:
                token_file.write(f'{email}:{password}:{token}\n')
        else:
            with open('../data/unclaimed.txt', 'a+') as token_file:
                token_file.write(f'{token}\n')

if __name__ == '__main__':
    AntiDebug().start()
    App = Client("351374883633512475858", "175215", "ZsrRIzwdluDe7Edg5TdlA6jIcm3DEQOg03L")
    Console.print_logo()

    if config['username'] == '' and config['password'] == '':
        print('''
        -> Welcome, to please provide informations to start.
            *~> If you have an issue please join our telegram.
            *~> Don't provide fake informations, they will be used to reset settings if you have problems !
        ''')

        email = input("[+] Email: ")
        license_key = input("[+] License key: ")
        username = input("[+] Username: ")
        password = input("[+] Password: ")

        try:
            App.register(license_key, email, username, password)
            print('Success !')
            input('')
        except Exception as e:
            print(e)
            sys.exit(0)

        sys.exit(0)
    else:
        try:
            App.login(config['username'], config['password'])

            threading.Thread(target=Console.title_thread).start()
            threading.Thread(target=Console.key_bind_thread).start()

            while True:
                while threading.active_count() >= config['threads'] + 3:
                    time.sleep(1)

                CreatorWorker().start()
        except:
            print('''
                    -> An issue was found when we are connecting to your account.
                        *~> Be sure to put your username/password in config.json.
                        *~> If you need key join telegram channel.
                    ''')
            input('')
            sys.exit(0)