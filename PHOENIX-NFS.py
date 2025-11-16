

from flask import Flask, render_template_string, request
from cryptography.fernet import Fernet
import os, hashlib, base64, datetime, sqlite3, platform, uuid, subprocess

app = Flask(__name__)

def gds():
    try:
        output = subprocess.check_output("wmic diskdrive get serialnumber", shell=True)
        lines = output.decode().splitlines()
        serials = [line.strip() for line in lines if line.strip() and "SerialNumber" not in line]
        return serials[0] if serials else "unknown"
    except:
        return "unknown"

def gdc():
    mac = str(uuid.getnode())
    node = platform.node()
    system = platform.system()
    release = platform.release()
    disk_serial = gds()
    raw = f"{mac}{node}{system}{release}{disk_serial}"
    return hashlib.sha256(raw.encode()).hexdigest(), raw

def generate_key(password):
    key = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(key[:32])

HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NFS – National File Security</title>
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@600&family=Poppins:wght@400;600&display=swap" rel="stylesheet">
    <style>
        *{margin:0;padding:0;box-sizing:border-box;}
        body{
            height:100vh;
            background:;
            font-family:'Poppins',sans-serif;
            background: #212121;
            color: #212121;
            display:flex;
            align-items:center;
            justify-content:center;
            overflow:hidden;
        }
        .container{
            text-align:center;
            padding:50px;
            border-radius:30px;
            backdrop-filter:blur(30px);
            background:rgba(255,255,255,0.040);
            width:90%;
            max-width:800px;
            transition:all 0.5s ease;
        }
        .title{
            font-family:'Orbitron',sans-serif;
            font-size:28px;
            letter-spacing:2px;
            color:cyan;
            font-weight:bold;
            text-transform:uppercase;
            margin-bottom:50px;
        }
        .buttons{
            display:flex;
            justify-content:center;
            gap:40px;
            flex-wrap:wrap;
            margin-bottom:40px;
        }
        button{
            font-family:'Poppins',sans-serif;
            font-size:18px;
            font-weight:600;
            padding:15px 40px;
            border:none;
            border-radius:50px;
            color:white;
            background:linear-gradient(90deg,#00bcd4,#0066ff);
            cursor:pointer;
            transition:all 0.4s ease;
        }
        button:hover{
            transform:scale(1.05);
            background:linear-gradient(90deg,#00e5ff,#0099ff);
            box-shadow:0 0 15px cyan;
        }
        .path-label{
            font-size:16px;
            margin-bottom:25px;
            color:rgba(255,255,255,0.8);
        }
        input[type="password"]{
            width:70%;
            max-width:400px;
            padding:14px 20px;
            font-size:18px;
            color:white;
            border:none;
            border-radius:50px;
            text-align:center;
            background:rgba(255,255,255,0.05);
            backdrop-filter:blur(15px);
            outline:none;
            transition:all 0.3s ease;
            font-style:italic;
        }
        input[type="password"]:focus{
            box-shadow:0 0 10px cyan;
            transform:scale(1.02);
        }
        .done-btn{
            margin-top:40px;
            background:linear-gradient(90deg,#00ffb3,#00bfa5);
        }
        .done-btn:hover{box-shadow:0 0 15px #00ffcc;}
        footer{
            position:absolute;
            bottom:20px;
            font-size:14px;
            color:rgba(255,255,255,0.5);
            letter-spacing:1px;
        }
        @media(max-width:600px){
            .buttons{flex-direction:column;gap:20px;}
            .container{padding:30px;}
            .title{font-size:22px;}
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="title">NFS – National File Security</div>
        <form method="POST" enctype="multipart/form-data">
            <div class="buttons">
                <button name="mode" value="encrypt">Encrypt</button>
                <button name="mode" value="decrypt">Decrypt</button>
            </div>
            <div class="path-label">{{ message }}</div>
            <input type="file" name="file"><br><br>
            <input type="password" name="password" placeholder="Enter your password"><br>
            <button class="done-btn" type="submit">Done</button>
        </form>
    </div>
    <footer>© 2025 PHOENIX</footer>
</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def home():
    message = "No file selected"
    if request.method == "POST":
        mode = request.form.get("mode")
        password = request.form.get("password")
        file = request.files.get("file")

        if not password or not file:
            message = "Please select a file and enter password."
        else:
            key = generate_key(password)
            fernet = Fernet(key)
            device_code, _ = gdc()
            filename = file.filename
            filepath = os.path.join("temp_" + filename)
            file.save(filepath)

            if mode == "encrypt":
                with open(filepath, "rb") as f:
                    data = f.read()
                encrypted = fernet.encrypt(data)
                outpath = filepath + ".secure"
                with open(outpath, "wb") as f:
                    f.write(encrypted)
                os.remove(filepath)

                conn = sqlite3.connect("secure_files.db")
                cur = conn.cursor()
                cur.execute("""CREATE TABLE IF NOT EXISTS logs(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    filename TEXT, password_hash TEXT, device_code TEXT, created_at TEXT)""")
                cur.execute("INSERT INTO logs(filename,password_hash,device_code,created_at) VALUES(?,?,?,?)",
                    (os.path.basename(outpath), hashlib.sha256(password.encode()).hexdigest(), device_code, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
                conn.commit()
                conn.close()
                message = f"✅ File encrypted successfully: {outpath}"

            elif mode == "decrypt":
                conn = sqlite3.connect("secure_files.db")
                cur = conn.cursor()
                cur.execute("SELECT * FROM logs WHERE filename=? AND password_hash=?",
                            (filename, hashlib.sha256(password.encode()).hexdigest()))
                row = cur.fetchone()
                conn.close()

                if not row:
                    message = "❌ Password incorrect or file not registered."
                elif row[3] != device_code:
                    message = "❌ Device mismatch! Unauthorized."
                else:
                    with open(filepath, "rb") as f:
                        enc_data = f.read()
                    try:
                        dec = fernet.decrypt(enc_data)
                        outpath = filepath.replace(".secure", "")
                        with open(outpath, "wb") as f:
                            f.write(dec)
                        os.remove(filepath)
                        message = f"✅ File decrypted successfully: {outpath}"
                    except:
                        message = "❌ Decryption failed. Wrong password or corrupted file."

    return render_template_string(HTML, message=message)

if __name__ == "__main__":
    app.run(debug=True)
