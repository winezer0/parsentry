from flask import Flask, request, render_template_string
import sqlite3
import os

app = Flask(__name__)


# Vulnerable database initialization
def init_db():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT)""")
    c.execute(
        "INSERT OR IGNORE INTO users (id, username, password) VALUES (1, 'admin', 'admin123')"
    )
    conn.commit()
    conn.close()


@app.route("/")
def index():
    return """
    <h1>Vulnerable Python Application</h1>
    <ul>
        <li><a href="/sqli">SQL Injection</a></li>
        <li><a href="/xss">XSS</a></li>
        <li><a href="/cmdi">Command Injection</a></li>
    </ul>
    """


# Vulnerability 1: SQL Injection
@app.route("/sqli")
def sql_injection():
    username = request.args.get("username", "")

    # Vulnerable SQL query - DO NOT USE IN PRODUCTION
    query = f"SELECT * FROM users WHERE username = '{username}'"

    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    try:
        results = c.execute(query).fetchall()
    except Exception as e:
        results = str(e)
    conn.close()

    return f"""
    <h2>SQL Injection Example</h2>
    <form>
        <input type="text" name="username" value="{username}">
        <input type="submit" value="Search">
    </form>
    <pre>Query: {query}</pre>
    <pre>Results: {results}</pre>
    """


# Vulnerability 2: Cross-Site Scripting (XSS)
@app.route("/xss")
def xss():
    name = request.args.get("name", "")

    # Vulnerable template - DO NOT USE IN PRODUCTION
    template = f"""
    <h2>XSS Example</h2>
    <form>
        <input type="text" name="name" value="{name}">
        <input type="submit" value="Greet">
    </form>
    <div>Hello, {name}!</div>
    """

    return render_template_string(template)


# Vulnerability 3: Command Injection
@app.route("/cmdi")
def command_injection():
    hostname = request.args.get("hostname", "localhost")

    # Vulnerable command execution - DO NOT USE IN PRODUCTION
    output = os.popen(f"ping -c 1 {hostname}").read()

    return f"""
    <h2>Command Injection Example</h2>
    <form>
        <input type="text" name="hostname" value="{hostname}">
        <input type="submit" value="Ping">
    </form>
    <pre>{output}</pre>
    """


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
