# from flask import Flask, render_template, request, url_for, redirect
# import os
# import sys
# import json
# from datetime import datetime

# app = Flask(__name__)

# DATA = os.path.join(os.getcwd(), "data")
# ADMIN_PASTES = os.path.join(os.getcwd(), "data", "admin")
# ANON_PASTES = os.path.join(os.getcwd(), "data", "other")

# with open(os.path.join(DATA, "template"), "r", encoding="utf-8") as temp_file:
#     _DEFAULT_POST_TEMPLATE = temp_file.read()

# admin_posts_list = [OWNER]
# anon_posts_list = []
# loosers_list = []


# def refreshLoosers():
#     global loosers_list
#     with open(os.path.join(DATA, "hol.json"), "r", encoding="utf-8") as file:
#         data = json.load(file)

#     if not(len(loosers_list) == len(data["loosers"])):
#         loosers_list = []
#         for looser in data["loosers"]:
#             if isinstance(looser, dict):
#                 loosers_list.append(looser)


# def refreshAdminPosts(): # Cruiq
#     global admin_posts_list
#     admin_posts_file_list = os.listdir(ADMIN_PASTES)
#     admin_posts_list = []
#     for admin_post_file_name in admin_posts_file_list:
#         admin_post_file_name_path = os.path.join(
#             ADMIN_PASTES, admin_post_file_name)
#         admin_post_file_name_stats = os.stat(admin_post_file_name_path)
#         admin_posts_list.append(
#             {
#                 "name": admin_post_file_name,
#                 "size": bytes2KB(admin_post_file_name_stats.st_size),
#                 "creation_date": datetime.utcfromtimestamp(int(admin_post_file_name_stats.st_mtime)).strftime('%d-%m-%Y'),
#                 "creation_time": datetime.utcfromtimestamp(int(admin_post_file_name_stats.st_mtime)).strftime('%H:%M:%S')
#             }
#         )


# def refreshAnonPosts(): # Cruiq
#     global anon_posts_list
#     anon_posts_file_list = os.listdir(ANON_PASTES)
#     anon_posts_list = []
#     for anon_post_file_name in anon_posts_file_list:
#         anon_post_file_name_path = os.path.join(
#             ANON_PASTES, anon_post_file_name)
#         anon_post_file_name_stats = os.stat(anon_post_file_name_path)
#         anon_posts_list.append(
#             {
#                 "name": anon_post_file_name,
#                 "size": bytes2KB(anon_post_file_name_stats.st_size),
#                 "creation_date": datetime.utcfromtimestamp(int(anon_post_file_name_stats.st_mtime)).strftime('%d-%m-%Y'),
#                 "creation_time": datetime.utcfromtimestamp(int(anon_post_file_name_stats.st_mtime)).strftime('%H:%M:%S')
#             }
#         ) 


# def bytes2KB(value):
#     return value / 1000


# @app.route("/")
# def index():
#     global admin_posts_list, anon_posts_list

#     refreshAdminPosts()
#     refreshAnonPosts()

#     return render_template("index.html", admin_posts_list=admin_posts_list, anon_posts_list=anon_posts_list)


# @app.route("/new")
# def new_paste():
#     return render_template("new.html", paste_template_text=_DEFAULT_POST_TEMPLATE)


# @app.route("/new_paste", methods=['POST'])
# def new_paste_form_post():
#     global _DEFAULT_POST_TEMPLATE
#     try:
#         args = request.values
#         pasteTitle = str(args.get('pasteTitle')).replace("/", "%2F")
#         pasteContent = args.get('pasteContent')
#     except Exception as e:
#         return f"Error: {e}"

#     with open(os.path.join(ANON_PASTES, pasteTitle), "w", encoding="utf-8") as file:
#         file.write(pasteContent)
#     return redirect(url_for('index'))


# @app.route("/post/<file>")
# def post(file):
#     filename = os.path.join(ANON_PASTES, file)
#     with open(filename, "r", encoding="utf-8") as filec:
#         content = filec.read()
#     stats = os.stat(filename)
#     creation_date = datetime.utcfromtimestamp(
#         int(stats.st_mtime)).strftime('%d-%m-%Y')
#     creation_time = datetime.utcfromtimestamp(
#         int(stats.st_mtime)).strftime('%H:%M:%S')
#     size = bytes2KB(stats.st_size)
#     return render_template(
#         "post.html",
#         filename=file,
#         file_content=content,
#         creation_date=creation_date,
#         creation_time=creation_time,
#         size=size
#     )


# @app.route("/admin/<file>")
# def admin_post(file):
#     filename = os.path.join(ADMIN_PASTES, file)
#     with open(filename, "r", encoding="utf-8") as filec:
#         content = filec.read()
#     stats = os.stat(filename)
#     creation_date = datetime.utcfromtimestamp(
#         int(stats.st_mtime)).strftime('%d-%m-%Y')
#     creation_time = datetime.utcfromtimestamp(
#         int(stats.st_mtime)).strftime('%H:%M:%S')
#     size = bytes2KB(stats.st_size)
#     return render_template(
#         "admin.html",
#         filename=file,
#         file_content=content,
#         creation_date=creation_date,
#         creation_time=creation_time,
#         size=size
#     )


# @app.route("/tos")
# def tos():
#     with open(os.path.join(DATA, "tos"), "r", encoding="utf-8") as file:
#         filec = file.read()
#     return render_template("tos.html", file_content=filec)


# @app.route("/hol")
# def hall_of_loosers():
#     global loosers_list
#     refreshLoosers()
#     return render_template(
#         "hol.html",
#         loosers_list=loosers_list
#     )


# @app.route("/links")
# @app.route("/pages")
# def list_of_pages():
#     return render_template("pages.html")


# if __name__ == "__main__":
#     app.run("0.0.0.0", port=8080, debug=False)

from flask import Flask, render_template, request, redirect, session, url_for
import os
import requests
import json
from datetime import datetime, timedelta
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import pytz

app = Flask(__name__)
app.secret_key = 'R§:d&875er6&U%RV'

try:

    conn = sqlite3.connect('database.db', check_same_thread=False)
    cursor = conn.cursor()

except:
    pass

def initdb():
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            status TEXT DEFAULT 'user',
            datejoin TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS pasts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner TEXT NOT NULL,
            pastname TEXT NOT NULL,
            date TEXT NOT NULL,
            hour TEXT NOT NULL,
            view TEXT NOT NULL,
            pin TEXT NOT NULL,
            ip TEXT NOT NULL,
            email TEXT,
            comments TEXT
        )
    ''')
    conn.commit()

def getip():
    if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
        return request.environ['REMOTE_ADDR']
    else:
        return request.environ['HTTP_X_FORWARDED_FOR']

DATA = os.path.join(os.getcwd(), "data")
ADMIN_PASTES = os.path.join(os.getcwd(), "data", "admin")
ANON_PASTES = os.path.join(os.getcwd(), "data", "other")

with open(os.path.join(DATA, "template"), "r", encoding="utf-8") as temp_file:
    _DEFAULT_POST_TEMPLATE = temp_file.read()

admin_posts_list = []
anon_posts_list = []
loosers_list = []


def refreshLoosers():
    global loosers_list
    with open(os.path.join(DATA, "hol.json"), "r", encoding="utf-8") as file:
        data = json.load(file)

    if not(len(loosers_list) == len(data["loosers"])):
        loosers_list = []
        for looser in data["loosers"]:
            if isinstance(looser, dict):
                loosers_list.append(looser)


def refreshAdminPosts(): # Cruiq
    global admin_posts_list
    admin_posts_file_list = os.listdir(ADMIN_PASTES)
    admin_posts_list = []
    for admin_post_file_name in admin_posts_file_list:
        admin_post_file_name_path = os.path.join(
            ADMIN_PASTES, admin_post_file_name)
        admin_post_file_name_stats = os.stat(admin_post_file_name_path)
        admin_posts_list.append(
            {
                "name": admin_post_file_name,
                "size": bytes2KB(admin_post_file_name_stats.st_size),
                "creation_date": datetime.utcfromtimestamp(int(admin_post_file_name_stats.st_mtime)).strftime('%d-%m-%Y'),
                "creation_time": datetime.utcfromtimestamp(int(admin_post_file_name_stats.st_mtime)).strftime('%H:%M:%S')
            }
        )

def refreshAnonPosts():
    try:
        global anon_posts_list, pinned_posts_list
        anon_posts_file_list = os.listdir(ANON_PASTES)
        
        anon_posts_list = []
        pinned_posts_list = []
        
        role_order = {"root": 0, "admin": 1, "mod": 2, "council": 3, "user": 4}
        
        for anon_post_file_name in anon_posts_file_list:
            cursor.execute("SELECT owner, date, hour, view, pin, comments FROM pasts WHERE pastname = ?", (anon_post_file_name,))
            result = cursor.fetchone()

            if result:
                pastownername = result[0]
                date_crt = result[1]
                hour_crt = result[2]
                view = result[3]
                pin = result[4] == "True" if isinstance(result[4], str) else bool(result[4])
                cursor.execute("SELECT * FROM users WHERE username = ?", (result[0],))
                resultg = cursor.fetchone()
                if resultg:
                    pastownerstatus = resultg[4]
                else:
                    pastownerstatus = "anonymous"
                comments = json.loads(result[5]) if result[5] else []
            else:
                pastownername = "Anonymous"
                view = "?"
                date_crt = "?"
                hour_crt = "?"
                pin = False
                pastownerstatus = "anonymous"
                comments = []

            post_data = {
                "name": anon_post_file_name,
                "pastowner": pastownername,
                "pastownerstatus": pastownerstatus,
                "view": view,
                "creation_date": date_crt,
                "creation_time": hour_crt,
                "pin": pin,
                "comments": comments
            }

            if post_data['pin']:
                pinned_posts_list.append(post_data)
            else:
                anon_posts_list.append(post_data)

        anon_posts_list = sorted(anon_posts_list, key=lambda x: (x['creation_date'], x['creation_time']), reverse=True)
        
        pinned_posts_list = sorted(
            pinned_posts_list,
            key=lambda x: (role_order.get(x['pastownerstatus'], 3), x['creation_date'], x['creation_time']),
            reverse=False
        )
    except:
        pass

def bytes2KB(value):
    return value / 1000

@app.route('/register', methods=['GET', 'POST'])
def register():

    global _DEFAULT_POST_TEMPLATE
    
    error = None
    if request.method == 'POST':
        
        args = request.values
        captcha_response = args.get('g-recaptcha-response')

        captcha_secret_key = '6Lfjmy4qAAAAAGSN0Gywy3-hScU0Fu2FWR1NbOcx'
        captcha_verify_url = 'https://www.google.com/recaptcha/api/siteverify'
        captcha_data = {
            'secret': captcha_secret_key,
            'response': captcha_response
        }
        captcha_verification_response = requests.post(captcha_verify_url, data=captcha_data)
        captcha_verification_result = captcha_verification_response.json()

        # captcha_verification_result = {'success': True} 

        if captcha_verification_result['success']:

            username = request.form['username']
            password = request.form['password']
            email = request.form['email']
            # email = request.form['email']
            ip_address = getip()

            cursor.execute("SELECT * FROM users WHERE ip_address=?", (ip_address,))
            existing_user = cursor.fetchone()

            if existing_user:
                error = 'An account is already registered with this IP address.'
            else:
                cursor.execute("SELECT * FROM users WHERE username=?", (username,))
                existing_username = cursor.fetchone()
                
                if existing_username:
                    error = 'Username already exists.'
                else:
                    hashed_password = generate_password_hash(password)
                    
                    moscow_tz = pytz.timezone('Europe/Moscow')
                    now = datetime.now(moscow_tz)
                    datejoin = now.strftime('%d-%m-%Y %H:%M:%S')

                    if email:

                        cursor.execute(
                            "INSERT INTO users (username, password, ip_address, datejoin, email) VALUES (?, ?, ?, ?, ?)",
                            (username, hashed_password, ip_address, datejoin, email)
                        )
                        conn.commit()
                    else:
                        cursor.execute(
                            "INSERT INTO users (username, password, ip_address, datejoin, email) VALUES (?, ?, ?, ?, ?)",
                            (username, hashed_password, ip_address, datejoin, email)
                        )
                        conn.commit()
            
                    session['username'] = username
                    session.permanent = True 
                    return redirect(url_for('index'))
                
        else:
            error = "CAPTCHA verification failed. Please try again."
    
    return render_template("register.html", paste_template_text=_DEFAULT_POST_TEMPLATE, error=error)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        global _DEFAULT_POST_TEMPLATE

        args = request.values
        captcha_response = args.get('g-recaptcha-response')

        captcha_secret_key = '6Lfjmy4qAAAAAGSN0Gywy3-hScU0Fu2FWR1NbOcx'
        captcha_verify_url = 'https://www.google.com/recaptcha/api/siteverify'
        captcha_data = {
            'secret': captcha_secret_key,
            'response': captcha_response
        }
        captcha_verification_response = requests.post(captcha_verify_url, data=captcha_data)
        captcha_verification_result = captcha_verification_response.json()

        if captcha_verification_result['success']:
            username = request.form['username']
            password = request.form['password']
            ip_address = getip()

            cursor.execute("SELECT * FROM users WHERE username=?", (username,))
            user = cursor.fetchone()

            if user and check_password_hash(user[2], password):
                session['username'] = username
                session.permanent = True 
                return redirect(url_for('index'))
            else:
                error = 'Invalid credentials. Please try again.'
        else:
            error = "CAPTCHA verification failed. Please try again."

    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route("/")
def index():
    global admin_posts_list, anon_posts_list

    refreshAnonPosts()

    return render_template('index.html', pinned_posts_list=pinned_posts_list, anon_posts_list=anon_posts_list, username=session.get('username'))

@app.route("/new")
def new_paste():
        return render_template("new.html", username=session.get('username'))

@app.route("/users")
def users():
    root_users = conn.execute('SELECT * FROM users WHERE status = "root"').fetchall()
    admin_users = conn.execute('SELECT * FROM users WHERE status = "admin"').fetchall()
    council_users = conn.execute('SELECT * FROM users WHERE status = "council"').fetchall()
    mod_users = conn.execute('SELECT * FROM users WHERE status = "mod"').fetchall()
    regular_users = conn.execute('SELECT * FROM users WHERE status = "user"').fetchall()

    return render_template("users.html", 
                           root_users=root_users, 
                           admin_users=admin_users, 
                           council_users=council_users,
                           mod_users=mod_users,
                           regular_users=regular_users, 
                           username=session.get('username'))

@app.route("/content")
def content():
    return render_template("content.html", paste_template_text=_DEFAULT_POST_TEMPLATE, username=session.get('username'))

@app.route("/new_paste", methods=['POST'])
def new_paste_form_post():
    global _DEFAULT_POST_TEMPLATE

    args = request.values
    captcha_response = args.get('g-recaptcha-response')

    captcha_secret_key = '6Lfjmy4qAAAAAGSN0Gywy3-hScU0Fu2FWR1NbOcx'
    captcha_verify_url = 'https://www.google.com/recaptcha/api/siteverify'
    captcha_data = {
        'secret': captcha_secret_key,
        'response': captcha_response
    }
    captcha_verification_response = requests.post(captcha_verify_url, data=captcha_data)
    captcha_verification_result = captcha_verification_response.json()

    # captcha_verification_result = {'success': True} 

    if captcha_verification_result['success']:
        try:
            args = request.values
            pasteTitle = str(args.get('pasteTitle')).replace("/", "%    2F")
            pasteContent = args.get('pasteContent')

            if len(pasteTitle) < 3 or len(pasteTitle) > 25:
                error_message = "Title must be between 3 and 25 characters."
                return render_template("new.html", paste_template_text=_DEFAULT_POST_TEMPLATE, error=error_message, username=session.get('username'))

            elif len(pasteContent) < 10 or len(pasteContent) > 25000:
                error_message = "Content must be between 10 and 25,000 characters."
                return render_template("new.html", paste_template_text=_DEFAULT_POST_TEMPLATE, error=error_message, username=session.get('username'))
            
            file_path = os.path.join(ANON_PASTES, pasteTitle)
            if os.path.exists(file_path):
                error_message = "This title is already taken. Please choose a different title."
                return render_template("new.html", paste_template_text=_DEFAULT_POST_TEMPLATE, error=error_message, username=session.get('username'))

            ip_address = getip()
            username=session.get('username')

            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            bdus = cursor.fetchone()
            
            if bdus:
                statusus = bdus[4]
            else:
                statusus = "user"

            current_datetime = datetime.now()

            cursor.execute("SELECT date, hour FROM pasts WHERE ip = ? ORDER BY date DESC, hour DESC LIMIT 1", (ip_address,))
            last_paste = cursor.fetchone()

            if last_paste:
                last_paste_datetime = datetime.strptime(f"{last_paste[0]} {last_paste[1]}", '%d-%m-%Y %H:%M:%S')
                time_diff = current_datetime - last_paste_datetime

                if time_diff < timedelta(minutes=1):
                    if statusus == 'user':
                        cooldown_seconds = int(60 - time_diff.total_seconds())
                        error_message = f"Cooldown! Please wait {cooldown_seconds} seconds."
                        return render_template("new.html", paste_template_text=_DEFAULT_POST_TEMPLATE, error=error_message, username=session.get('username'))
                    else:
                        pass
                else:
                    pass

            if username:            
        
                pasteTitle = str(args.get('pasteTitle')).replace("/", "%    2F")
                pasteContent = args.get('pasteContent')

                current_datetime = datetime.now()
                date_formatted = current_datetime.strftime('%d-%m-%Y')
                hour_formatted = current_datetime.strftime('%H:%M:%S')

                cursor.execute("INSERT INTO pasts (owner, pastname, date, hour, view, pin, ip) VALUES (?, ?, ?, ?, ?, ?, ?)", 
                            (username, pasteTitle, date_formatted, hour_formatted, 0, 'False', ip_address))
                conn.commit()
        
            else: 
        
                args = request.values
                pasteTitle = str(args.get('pasteTitle')).replace("/", "%2F")
                pasteContent = args.get('pasteContent')
                captcha_response = args.get('g-recaptcha-response')

                current_datetime = datetime.now()
                date_formatted = current_datetime.strftime('%d-%m-%Y')
                hour_formatted = current_datetime.strftime('%H:%M:%S')

                cursor.execute("INSERT INTO pasts (owner, pastname, date, hour, view, pin, ip) VALUES (?, ?, ?, ?, ?, ?, ?)", 
                            ('Anonymous', pasteTitle, date_formatted, hour_formatted, 0, 'False', ip_address))
                conn.commit()
        except Exception as e:
            return f"Error: {e}"
        
        with open(os.path.join(ANON_PASTES, pasteTitle), "w", encoding="utf-8") as file:
            file.write(pasteContent)

        return redirect(url_for('index'))
    else:
        error_message = "CAPTCHA verification failed. Please try again."
        return render_template("new.html", paste_template_text=_DEFAULT_POST_TEMPLATE, error=error_message, username=session.get('username'))


@app.route('/delete_paste/<paste_name>', methods=['POST'])
def delete_paste(paste_name):

    username = session.get('username')
    
    cursor.execute("SELECT status FROM users WHERE username = ?", (username,))
    user_status = cursor.fetchone()
    
    if not user_status or user_status[0] not in ['root', 'admin', 'mod']:
        return redirect(url_for('post', file=paste_name))

    cursor.execute("DELETE FROM pasts WHERE pastname = ?", (paste_name,))

    file_path = os.path.join(ANON_PASTES, paste_name)
    try:
        os.remove(file_path)
    except:
        pass
    conn.commit()

    return redirect(url_for('index'))

@app.route('/toggle_pinned/<paste_name>', methods=['POST'])
def toggle_pinned(paste_name):

    username = session.get('username')
    
    cursor.execute("SELECT status FROM users WHERE username = ?", (username,))
    user_status = cursor.fetchone()
    
    if not user_status or user_status[0] not in ['root', 'admin', 'mod']:
        return redirect(url_for('post', file=paste_name))

    cursor.execute("SELECT pin FROM pasts WHERE pastname = ?", (paste_name,))
    result = cursor.fetchone()

    if result:
        current_status = result[0]
        if current_status == 'True':
            new_status = 'False'
        else:
            new_status = 'True'
        
        cursor.execute("UPDATE pasts SET pin = ? WHERE pastname = ?", (new_status, paste_name))
        conn.commit()
    
    return redirect(url_for('post', file=paste_name))

@app.route("/delete_comment/<file>/<comment_date>")
def delete_comment(file, comment_date):
    username = session.get('username')
    
    cursor.execute("SELECT status FROM users WHERE username = ?", (username,))
    user_status = cursor.fetchone()
    
    if not user_status or user_status[0] not in ['root', 'admin', 'mod']:
        return redirect(url_for('post', file=file))

    cursor.execute("SELECT comments FROM pasts WHERE pastname = ?", (file,))
    result = cursor.fetchone()
    
    if not result:
        return redirect(url_for('post', file=file))

    comments = json.loads(result[0]) if result[0] else []
    
    comments = [comment for comment in comments if comment['date'] != comment_date]

    cursor.execute("UPDATE pasts SET comments = ? WHERE pastname = ?", (json.dumps(comments), file))
    conn.commit()

    return redirect(url_for('post', file=file))

# @app.route("/profile/<username>")
# def profile(username):
#     cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
#     result = cursor.fetchone()

#     if result:
#         id = result[0]
#         username = result[1]
#         datejoin = result[5]
#     else:
#         return redirect(url_for('index'))

#     return render_template(
#         "profile.html",
#         id=id,
#         username=username,
#         datejoin=datejoin
#     )

def add_comment_to_post(file, login, comment):
    msk_tz = pytz.timezone('Europe/Moscow')
    now = datetime.now(msk_tz)
    formatted_date = now.strftime('%Y-%m-%d %H:%M:%S')

    cursor.execute("SELECT comments FROM pasts WHERE pastname = ?", (file,))
    result = cursor.fetchone()

    if result:
        comments = json.loads(result[0]) if result[0] else []
    else:
        comments = []

    ip_address = getip()

    new_comment = {
        "login": login,
        "date": formatted_date,
        "comment": comment,
        "ip_address": ip_address
    }

    comments.append(new_comment)

    cursor.execute("UPDATE pasts SET comments = ? WHERE pastname = ?", (json.dumps(comments), file))
    conn.commit()

@app.route("/user/<username>")
def user(username):
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    
    if result is None:
        return redirect(url_for('index'))

    cursor.execute("SELECT * FROM pasts WHERE owner = ?", (username,))
    pastes = cursor.fetchall()

    cursor.execute("SELECT COUNT(*) FROM pasts WHERE owner = ?", (username,))
    paste_count = cursor.fetchone()[0]

    paste_comments_count = {}
    total_comments = 0

    for paste in pastes:
        paste_id = paste[0]
        cursor.execute("SELECT comments FROM pasts WHERE id = ?", (paste_id,))
        comments_json = cursor.fetchone()[0]
        comments_list = json.loads(comments_json) if comments_json else []
        comment_count = len(comments_list)
        paste_comments_count[paste_id] = comment_count
        total_comments += comment_count

    pastes_sorted = sorted(pastes, key=lambda x: (x[3], x[4]), reverse=True)

    return render_template(
        "profile.html",
        login=username,
        status=result[4],
        userid=result[0],
        joined=result[5],
        paste_count=paste_count,
        pastes=pastes_sorted,
        comments=total_comments,
        paste_comments_count=paste_comments_count,
        username=session.get('username')
    )

@app.route("/post/<file>")
def post(file):
    filename = os.path.join(ANON_PASTES, file)
    try:
        with open(filename, "r", encoding="utf-8") as filec:
            content = filec.read()
    except:
        return redirect(url_for('index'))

    cursor.execute("SELECT owner, date, hour, view, pin, comments FROM pasts WHERE pastname = ?", (file,))
    result = cursor.fetchone()

    cursor.execute("SELECT view FROM pasts WHERE pastname = ?", (file,))
    resultk = cursor.fetchone()

    if resultk:
        current_views = int(resultk[0])
        new_views = current_views + 1

        cursor.execute("UPDATE pasts SET view = ? WHERE pastname = ?", (new_views, file))
        conn.commit()

    username = session.get('username')

    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    bdus = cursor.fetchone()
    
    if bdus:
        statusus = bdus[4]
    else:
        statusus = "anonymous"

    if result:
        owner = result[0]
        creation_date = result[1]
        creation_time = result[2]
        view = result[3]
        is_pinned = result[4]
        comments = json.loads(result[5]) if result[5] else []
        status = statusus
    else:
        owner = "Anonymous"
        creation_date = "?"
        creation_time = "?"
        view = "?"
        is_pinned = "False"
        comments = []
        status = statusus

    for comment in comments:
        comment_login = comment.get('login')
        cursor.execute("SELECT status FROM users WHERE username = ?", (comment_login,))
        user_status = cursor.fetchone()
        comment['loginstatus'] = user_status[0] if user_status else "anonymous"

    comments = sorted(comments, key=lambda x: x['date'], reverse=True)

    return render_template(
        "post.html",
        filename=file,
        ownerpast=owner,
        file_content=content,
        creation_date=creation_date,
        creation_time=creation_time,
        view=view,
        is_pinned=is_pinned,
        comments=comments,
        username=username,
        status=status
    )

def get_comment_statuses(comments):
    for comment in comments:
        comment_login = comment.get('login')
        cursor.execute("SELECT status FROM users WHERE username = ?", (comment_login,))
        user_status = cursor.fetchone()
        comment['loginstatus'] = user_status[0] if user_status else "anonymous"
    return sorted(comments, key=lambda x: x['date'], reverse=True)

@app.route("/post/<file>/add_comment", methods=["POST"])
def add_comment(file):
    args = request.values
    captcha_response = args.get('g-recaptcha-response')

    captcha_secret_key = '6Lfjmy4qAAAAAGSN0Gywy3-hScU0Fu2FWR1NbOcx'
    captcha_verify_url = 'https://www.google.com/recaptcha/api/siteverify'
    captcha_data = {
        'secret': captcha_secret_key,
        'response': captcha_response
    }
    captcha_verification_response = requests.post(captcha_verify_url, data=captcha_data)
    captcha_verification_result = captcha_verification_response.json()

    username = session.get('username')
    login = username if username else "Anonymous"
    ip_address = getip()

    try:
        cursor.execute("SELECT owner, date, hour, view, pin FROM pasts WHERE pastname = ?", (file,))
        result = cursor.fetchone()
        
        if result:
            owner, creation_date, creation_time, view, is_pinned = result
        else:
            owner = "Anonymous"
            creation_date = "?"
            creation_time = "?"
            view = "?"
            is_pinned = "False"

        cursor.execute("SELECT login, comment, date FROM comments WHERE pastname = ?", (file,))
        comments = cursor.fetchall()
        
        filename = os.path.join(ANON_PASTES, file)
        with open(filename, "r", encoding="utf-8") as filec:
            content = filec.read()
        
        if captcha_verification_result['success']:
            comment = request.form.get("comment")

            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            bdus = cursor.fetchone()
            statusus = bdus[4] if bdus else "anonymous"

            if login and comment:
                comments = json.loads(result[0]) if result[0] else []
                msk_tz = pytz.timezone('Europe/Moscow')
                now = datetime.now(msk_tz)

                for past_comment in comments:
                    comment_ip = past_comment.get('ip_address')
                    comment_date = past_comment.get('date')

                    comment_datetime = datetime.strptime(comment_date, '%Y-%m-%d %H:%M:%S')
                    comment_datetime = msk_tz.localize(comment_datetime)

                    if comment_ip == ip_address:
                        time_difference = (now - comment_datetime).total_seconds()
                        if time_difference < 60:
                            if statusus in ['user', 'anonymous']:
                                cooldown_seconds = int(60 - time_difference)

                                comments = get_comment_statuses(comments)

                                return render_template(
                                    "post.html",
                                    filename=file,
                                    ownerpast=owner,
                                    file_content=content,
                                    creation_date=creation_date,
                                    creation_time=creation_time,
                                    view=view,
                                    status=statusus,
                                    is_pinned=is_pinned,
                                    comments=comments,
                                    username=username,
                                    error=f"Cooldown! Please wait {cooldown_seconds} seconds."
                                )

                add_comment_to_post(file, login, comment)
                return redirect(url_for('post', file=file))
        else:
           return redirect(url_for('index'))
    except:
        return redirect(url_for('index'))


@app.route("/tos")
def tos():
    with open(os.path.join(DATA, "tos"), "r", encoding="utf-8") as file:
        filec = file.read()
    return render_template("tos.html", file_content=filec)


@app.route("/hoa")
def hall_of_loosers():
    global loosers_list
    refreshLoosers()
    return render_template(
        "hoa.html",
        loosers_list=loosers_list,
        username=session.get('username')
    )

if __name__ == "__main__":
    initdb()
    app.run("0.0.0.0", port=8080, debug=False)
