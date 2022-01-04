import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user_id = session["user_id"]
    
    stocks = db.execute("SELECT symbol, name, price, SUM(shares) as totalShares FROM transactions  WHERE user_id = ? GROUP BY symbol", user_id)
    cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]
    
    total = cash
    
    for stock in stocks:
        total += stock["price"] * stock["totalShares"]
    
    return render_template("index.html", stocks=stocks, cash=cash, usd=usd, total=total)

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol").upper()
        item = lookup(symbol)
        
        if not symbol:
            return apology("Please Enter A Symbol!")
        elif not item:
            return apology("Invalid Symbol!")
            
        try:
            shares = int(request.form.get("shares"))
        except:
            return apology("Shares Must Be Ineger!")
            
        if shares <= 0:
            return apology("Shares Must Be A Postive Integer!")
            
        user_id = session["user_id"]
        cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]
        
        item_name = item["name"]
        item_price = item["price"]
        total_price = item_price * shares
        
        if cash < total_price:
            return apology("Not Enough Cash!")
        else:
            db.execute("UPDATE users SET cash = ? WHERE id = ?", cash - total_price, user_id)
            db.execute("INSERT INTO transactions (user_id, name, shares, price, type, symbol) VALUES (?, ?, ?, ?, ?, ?)",
                        user_id, item_name, shares, item_price, 'buy', symbol)
        
        return redirect('/')
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    return apology("TODO")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        
        if not symbol:
            return apology("PLease Enter A Symbol!")
            
        item = lookup(symbol)
        
        if not item:
            return apology("Invalid Symbol!")
        
        return render_template("quoted.html", item=item, usd_function=usd)
    else:
        return render_template("quote.html")
    


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        # Ensure the username was submitted
        if not username:
            return apology("must provide username", 400)
        # Ensure the username doesn't exists
        elif len(rows) != 0:
            return apology("username already exists", 400)

        # Ensure password was submitted
        elif not password:
            return apology("must provide password", 400)

        # Ensure confirmation password was submitted
        elif not request.form.get("confirmation"):
            return apology("must provide a confirmation password", 400)

        # Ensure passwords match
        elif not password == confirmation:
            return apology("passwords must match", 400)

        else:
            # Generate the hash of the password
            hash = generate_password_hash(
                password, method="pbkdf2:sha256", salt_length=8
            )
            # Insert the new user
            db.execute(
                "INSERT INTO users (username, hash) VALUES (?, ?) ", username, hash,
            )
            # Redirect user to home page
            return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    data = getStocks()
    if request.method == 'POST':
        user_id = session['user_id']
        result = { 'status' : False }
        symbol = request.form.get('symbol')
        shares = int(request.form.get('shares'))
        # validate input
        if not validate(symbol, shares):
            result['reason'] = "You must provide Shares & Symbol or Shares must be potive"
            return render_template("sell.html", result = result, data = data)
        # check if user can sell
        ownedShares = db.execute("SELECT SUM(shares) as shares FROM users_stocks WHERE shares > 0 AND user_id = :user_id AND stock = :symbol GROUP BY stock", user_id = user_id, symbol = symbol)
        if not ownedShares:
            result['reason'] = "You do not own the selected stock"
            return apology("You do not own the selected stock", code=400)
        elif not ownedShares[0]['shares'] >= shares:
            result['reason'] = "You do not have enough shares of the selected stock"
            return render_template("sell.html", result = result, data = data)
        else:
            # remove stocks from users portfolio
            quote = lookup(symbol)
            amount = quote['price'] * shares
            modStock(symbol, -shares)
            # update user cash
            storeTxn(amount, 'sold', symbol, shares)
            updateCash(amount)
    data = getStocks()
    return render_template("sell.html", data = data)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
