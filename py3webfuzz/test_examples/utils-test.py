'''
test utils functions


'''

url = "https://connect.qa.appetize-dev.com:443/login/validate"
cookies = {"__zlcmid": "14ck6vPJgcporvx", "csrf_cookie_name": "2fe3330027d04b4fd270df045958d512", "ci_session": "a%3A5%3A%7Bs%3A10%3A%22session_id%22%3Bs%3A32%3A%221fca3deae335277e3ac1e15a6ac6391a%22%3Bs%3A10%3A%22ip_address%22%3Bs%3A11%3A%2210.8.66.164%22%3Bs%3A10%3A%22user_agent%22%3Bs%3A115%3A%22Mozilla%2F5.0%20%28Windows%20NT%2010.0%3B%20Win64%3B%20x64%29%20AppleWebKit%2F537.36%20%28KHTML%2C%20like%20Gecko%29%20Chrome%2F91.0.4472.114%20Safari%2F537.36%22%3Bs%3A13%3A%22last_activity%22%3Bi%3A1625163563%3Bs%3A9%3A%22user_data%22%3Bs%3A0%3A%22%22%3B%7D4d169af218752a5de1d112f34eb874da"}
headers = {"Connection": "close", "sec-ch-ua": "\"Chromium\";v=\"91\", \" Not;A Brand\";v=\"99\"", "Accept": "application/json, text/javascript, */*; q=0.01", "X-Requested-With": "XMLHttpRequest", "sec-ch-ua-mobile": "?0", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36", "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8", "Origin": "https://connect.qa.appetize-dev.com", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty", "Referer": "https://connect.qa.appetize-dev.com/login", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9"}
data = {"csrf_test_name": "2fe3330027d04b4fd270df045958d512", "login": "jonathan.angeles", "password": "vAEt5F^7a%"}


proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}

from py3webfuzz.utils import make_request
from py3webfuzz.fuzzdb import Attack


if __name__ == "__main__":
    attack = Attack.AttackPayloads


    req = make_request(url="https://connect.qa.appetize-dev.com:443/login/validate",
                       method="post",
                       headers=headers,
                       proxies=proxies,
                       #params=data,
                       data=data,
                       session_req=True,
                       cookies=cookies
                       )

    for key, value in req.cookies.get_dict().items():
        print(key, value)





