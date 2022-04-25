import httpx

# lol the v1 dont cry the shit code


class CookieBypass:
    def __init__(self):
        self.req_id = '6d8fd604c8d30893'

    def generate_cookie(self):
        payload = {
            "m": "3fUyucljT2VY8y4A.Mi76agwNahfgESSm9UMaB9japs-1644102877-0-Afj/4jAjiZ+1yjU95eDq9bpdzQ1AoaaiqDp6at2t2T+0V0ZgCJlx2EPXdYjZ5PIQf3olsHWr3PrQz9EUelQ1nhdLGt1wJqg5vtrWoOJJUCoRyXD/N3vPl0Gr3a85i7IWo5u/4ZiawyZreMt64GCIe9M=",
            "results": ["e2b3bbe546adb50cb5803050a3fc394a", "08fa7022d77b93a60562c61915a57bcd"], "timing": 132,
            "fp": {"id": 3,
                   "e": {"r": [1920, 1080], "ar": [1040, 1920], "pr": 1, "cd": 24, "wb": "false", "wp": "false",
                         "wn": "false", "ch": "true", "ws": "false", "wd": "false"}}}

        headers = {
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.99 Safari/537.36',
            'sec-ch-ua': '" Not;A Brand";v="99", "Google Chrome";v="97", "Chromium";v="97"',
            'accept-language': 'fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7',
            'accept-encoding': 'gzip, deflate, br',
            'content-type': 'application/json',
            'sec-ch-ua-platform': '"Windows"',
            'referer': 'https://discord.com/',
            'origin': 'https://discord.com',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-ch-ua-mobile': '?0',
            'accept': '*/*',
        }

        with httpx.Client(headers=headers) as client:
            client.headers[
                'user-agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.99 Safari/537.36'
            response = client.post(f'https://discord.com/cdn-cgi/bm/cv/result?req_id={self.req_id}', json=payload)
            cookie = dict(response.cookies)['__cf_bm']

            print(f'[>] Bypassed cookie: {cookie[:15]}')
            return cookie
