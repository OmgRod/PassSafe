const express = require('express');
const bcrypt = require('bcrypt');
const mysql = require('mysql2');
const session = require('express-session');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const app = express();

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'password_manager'
});

app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
    secret: 'your_secret_key',
    resave: false,
    saveUninitialized: true
}));

// Helper function to encrypt and decrypt passwords
const algorithm = 'aes-256-cbc';
const key = crypto.randomBytes(32);
const iv = crypto.randomBytes(16);

function encrypt(text, masterPassword) {
    let cipher = crypto.createCipheriv(algorithm, Buffer.from(masterPassword), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text, masterPassword) {
    let textParts = text.split(':');
    let iv = Buffer.from(textParts.shift(), 'hex');
    let encryptedText = Buffer.from(textParts.join(':'), 'hex');
    let decipher = crypto.createDecipheriv(algorithm, Buffer.from(masterPassword), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}

// Routes
app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
        if (results.length > 0) {
            bcrypt.compare(password, results[0].password, (err, isMatch) => {
                if (isMatch) {
                    req.session.user = results[0];
                    res.redirect('/home');
                } else {
                    res.send('Incorrect Password!');
                }
            });
        } else {
            res.send('Username not found!');
        }
    });
});

app.get('/signup', (req, res) => {
    res.render('signup');
});

app.post('/signup', (req, res) => {
    const { username, password } = req.body;
    bcrypt.hash(password, 10, (err, hash) => {
        db.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hash], (err, results) => {
            if (err) throw err;
            res.redirect('/login');
        });
    });
});

app.get('/home', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    db.query('SELECT * FROM accounts WHERE user_id = ?', [req.session.user.id], (err, results) => {
        if (err) throw err;
        let decryptedAccounts = results.map(acc => ({
            id: acc.id,
            account_name: acc.account_name,
            login: acc.login,
            password: decrypt(acc.password, req.session.user.password)
        }));
        res.render('home', { accounts: decryptedAccounts });
    });
});

app.post('/add-account', (req, res) => {
    const { account_name, login, password } = req.body;
    if (!req.session.user) {
        return res.redirect('/login');
    }
    let encryptedPassword = encrypt(password, req.session.user.password);
    db.query('INSERT INTO accounts (user_id, account_name, login, password) VALUES (?, ?, ?, ?)', 
        [req.session.user.id, account_name, login, encryptedPassword], (err, results) => {
            if (err) throw err;
            res.redirect('/home');
        });
});

app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.redirect('/home');
        }
        res.clearCookie('connect.sid');
        res.redirect('/login');
    });
});

app.listen(3000, () => {
    console.log('Server started on port 3000');
});
