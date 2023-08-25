const express = require('express')
const session = require('express-session')
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const db = require('./db')
const { v4: uuidv4 } = require('uuid');
const bodyParser = require("body-parser");
const urlebcodedparser = bodyParser.urlencoded({ extended: false });

const verify = (username, password, done) => {
  db.users.findByUsername(username, (err, user) => {
      if (err) { return done(err) }
      if (!user) { return done(null, false) }
      if( !db.users.verifyPassword(user, password)) {
        return done(null, false)
      }
      return done(null, user)
  })
}

const options = {
  usernameField: "username",
  passwordField: "password",
}

passport.use('local', new LocalStrategy(options, verify))

passport.serializeUser((user, cb) => {
  cb(null, user.id)
})

passport.deserializeUser( (id, cb) => {
  db.users.findById(id,  (err, user) => {
    if (err) { return cb(err) }
    cb(null, user)
  })
})

const app = express()
app.set('view engine', 'ejs')

app.use(express.urlencoded());
app.use(session({ secret: 'SECRET'}));

app.use(passport.initialize())
app.use(passport.session())

app.get('/', (req, res) => {
    res.render('home', { user: req.user })
  })

app.get('/api/user/login', (req, res) => {
  res.render('login');
})

app.get('/api/user/me', (req, res, next) => {
    if (!req.isAuthenticated()) {
      return res.redirect('/login')
    }
    next()
  },
  (req, res) => {
    res.render('profile', { user: req.user })
  }
)

app.post('/api/user/login',
  passport.authenticate('local', { failureRedirect: '/api/user/login' }),
  (req, res) => {
    res.redirect('/')
  })

app.get('/api/user/signup', (req, res) => {
  res.render('signup')
})

app.post('/api/user/signup',
  urlebcodedparser,
  (req, res) => {
    const { username, password, displayName, emails} = req.body;
    const newUser = {
      id: uuidv4(),
      username,
      password,
      displayName,
      emails: [{ value: emails }],
    }
    console.log('newUser', newUser);
    db.users.postRecord(newUser);
    res.redirect('/');
    
  })

app.get('/logout',  (req, res) => {
    req.logout()
    res.redirect('/')
  })

const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
  console.log(`http://localhost:${PORT}`)
})