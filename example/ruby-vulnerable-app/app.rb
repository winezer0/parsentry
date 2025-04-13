require 'sinatra'
require 'sqlite3'

def init_db
  db = SQLite3::Database.new "users.db"
  db.execute <<-SQL
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY,
      username TEXT,
      password TEXT
    );
  SQL
  db.execute "INSERT OR IGNORE INTO users (id, username, password) VALUES (1, 'admin', 'admin123')"
  db.close
end

init_db

get '/' do
  <<-HTML
  <h1>Vulnerable Ruby Application</h1>
  <ul>
    <li><a href="/me">me</a></li>
  </ul>
  HTML
end

get '/me' do
  username = params['username'] || ""

  query = "SELECT * FROM users WHERE username = '#{username}'"

  begin
    db = SQLite3::Database.new "users.db"
    results = db.execute(query)
    db.close
  rescue => e
    results = e.message
  end

  <<-HTML
  <h2>Vulnerable Example</h2>
  <form>
    <input type="text" name="username" value="#{username}">
    <input type="submit" value="Search">
  </form>
  <pre>Query: #{query}</pre>
  <pre>Results: #{results}</pre>
  HTML
end
