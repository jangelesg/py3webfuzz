'''
test utils functions
'''

if __name__ == "__main__":

    from py3webfuzz import utils

    location = "http://127.0.0.1:8080/WebGoat/start.mvc#lesson/WebGoatIntroduction.lesson"
    headers = {"Host": "ssl.scroogle.org", "User-Agent": \
               "Mozilla/4.0 (compatible; MSIE 4.01; AOL 4.0; Mac_68K)",
               "Content-Type": "application/x-www-form-urlencoded"}

    res = utils.make_request(location, headers=headers, method="get")

    print(res)
