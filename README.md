<p align="center"> <img src="https://raw.githubusercontent.com/qeeqbox/session-fixation/main/content/session-fixation.svg"></p>

An application manages session identifiers in an insecure manner, making them susceptible to reuse by threat actors. Session identifiers are crucial for maintaining a user's authenticated session. If an application permits the reuse of a session identifier, a threat actor could trick a victim into logging in with a session identifier they already control. Once the victim successfully logs in, the threat actor can use that same session identifier to hijack the authenticated session and impersonate the legitimate user.

Clone this current repo recursively
```sh
git clone --recurse-submodules https://github.com/qeeqbox/session-fixation
```
Run the webapp using Python
```sh
python3 session-fixation/vulnerable-web-app/webapp.py
```
Open the webapp in your browser 127.0.0.1:5142
<p align="center"> <img src="https://raw.githubusercontent.com/qeeqbox/session-fixation/main/content/1.png"></p>
Use John's default credentials (username: john and password: john) to login
<p align="center"> <img src="https://raw.githubusercontent.com/qeeqbox/session-fixation/main/content/2.png"></p>
Open the Storage tab in the developer tools to examine the request cookies, note the session_id used for the current session
<p align="center"> <img src="https://raw.githubusercontent.com/qeeqbox/session-fixation/main/content/3.png"></p>
Open the private tab (or change the browser profile), type the webapp address in your browser 127.0.0.1:5142?session_id=<The session ID from the previous step>
<p align="center"> <img src="https://raw.githubusercontent.com/qeeqbox/session-fixation/main/content/4.png"></p>
Use Jane's default credentials (username: jane and password: jane) to login
<p align="center"> <img src="https://raw.githubusercontent.com/qeeqbox/session-fixation/main/content/5.png"></p>
Open the Storage tab in the developer tools to examine the request cookies, the session_id should be the same as John
<p align="center"> <img src="https://raw.githubusercontent.com/qeeqbox/session-fixation/main/content/6.png"></p>
Go to John's session and refresh the webpage, it will be Jane's session
<p align="center"> <img src="https://raw.githubusercontent.com/qeeqbox/session-fixation/main/content/5.png"></p>

## Code
When a user logs in to the page, the parameters like session_id are passed to the gen_cookie() function
```py
def do_POST(self):
    parsed_url = urllib_parse.urlparse(self.path)
    post_request_data_length = int(self.headers.get('content-length'))
    post_request_data = urllib_parse.parse_qs(str(self.rfile.read(post_request_data_length),"UTF-8"))
    query_request_data = urllib_parse.parse_qs(parsed_url.query)
    self.session = self.check_logged_in()
    if parsed_url.path == "/login" and "username" in post_request_data and "password" in post_request_data:
        ret = self.check_creds(post_request_data['username'][0],post_request_data['password'][0])
        if isinstance(ret, list) and ret[0] == "valid":
            self.send_content(302, self.gen_cookie(ret[1],60*15,query_request_data)+[('Location', URL)], None)
            self.log_message("%s logged in" % post_request_data['username'][0])
            return
        elif isinstance(ret, list) and ret[0] == "password":
            if "debug" in post_request_data:
                if post_request_data["debug"][0] == "1":
                    self.send_content(302, self.gen_cookie(ret[1],60*15,query_request_data)+[('Location', URL)], None)
                    self.log_message("%s logged in" % post_request_data['username'][0])
                    return
            self.send_content(401, [('Content-type', 'text/html')], self.msg_page(f"Password is wrong".encode("utf-8"), b"login"))
            return
        elif isinstance(ret, list) and ret[0] == "username" or isinstance(ret, list) and ret[0] == "error":
            self.send_content(401, [('Content-type', 'text/html')], self.msg_page(f"User {post_request_data['username'][0]} doesn't exist".encode("utf-8"), b"login"))
            return
```
The gen_cookie() function sets up the session_id with one passed from the request parameters if it exists
```py
    def gen_cookie(self, row, max_age, query):
        session_id = None
        cookies = SimpleCookie(self.headers.get('Cookie'))
        if 'session_id' in query:
            session_id = query['session_id'][0]
        elif 'session_id' in cookies:
            session_id = cookies['session_id'].value
        else:
            session_id = "".join(str(randint(1, 9)) for _ in range(5))
        #end_time = datetime.now() + timedelta(days=1)
        SESSIONS[session_id] = {"username":row[1], "department": row[3],"access":row[4], "is_admin":row[5]}
        cookie1 = SimpleCookie()
        cookie1['session_id'] = session_id
        cookie1['session_id']['path'] = '/'
        cookie1['session_id']['max-age'] = max_age
        cookie2 = SimpleCookie()
        cookie2['is_admin'] = row[5]
        cookie2['is_admin']['path'] = '/'
        cookie2['is_admin']['max-age'] = max_age
        cookie3 = SimpleCookie()
        cookie3['access'] = row[4]
        cookie3['access']['path'] = '/'
        cookie3['access']['max-age'] = max_age
        cookie4 = SimpleCookie()
        cookie4['department'] = row[3]
        cookie4['department']['path'] = '/'
        cookie4['department']['max-age'] = max_age
        cookies = [('Set-Cookie', cookie1.output(header='', sep='')),('Set-Cookie', cookie2.output(header='', sep='')),('Set-Cookie', cookie3.output(header='', sep='')),('Set-Cookie', cookie4.output(header='', sep=''))]
        return cookies
```