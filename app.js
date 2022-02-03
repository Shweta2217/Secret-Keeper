require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const session = require("express-session");
const SessionStore = require("connect-mongodb-session")(session);
const passport = require("passport");
const passportLocal = require("passport-local").Strategy;
const passCreate = require("./password").passCreate;
const Validate = require("./password").validate;
const GoogleStrategy = require("passport-google-oauth20").Strategy;

const app = express();

app.set("view engine", "ejs");

//-----------------------------MiddleWares------------------------------------------//
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

const Store = new SessionStore({
  uri: process.env.MONGO_URL,
  collection: "session",
});

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: Store,
  }),
);
//------------------------------Defining DB---------------------------------------//


mongoose.connect(process.env.MONGO_URL, (err) => {
  if (err) console.log(err);
  else console.log("SuccessFully Connected to DB");
});
//*** defigning Schema*/
const userSchema = new mongoose.Schema({
  username: String,
  salt: String,
  hash: String,
  googleId: String,
  secret:String
});

const User = mongoose.model("User", userSchema);

//----------------------------passport stuff----------------------------

const Customfield = {
  usernameField: "email",
  passwordField: "pass",
};

function verifyCallback(username, password, done) {
  User.findOne({ username: username }, (err, result) => {
    if (err) {
      return done(err);
    }
    if (!result) {
      return done(null, false);
    }
    if (result) {
      const isValid = Validate(password, result.salt, result.hash);
      if (isValid) {
        console.log("i am here 1");
        done(null, result);
      } else done(null, false);
    }
  });
}

//------create a local stragey---------
const localS = new passportLocal(Customfield, verifyCallback);

passport.use(localS);



//------create a Google stragey---------
const gStrategy ={
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/secrets",
};

function callback(accessToken, refreshToken, profile, done) {
User.findOne({ googleId: profile.id }, function (err, user) {
  if(err){
    return done(err, false);}
  else{
    if(user){
      return done(null, user);
    }
    else {
      const newGoogleUser = new User({
        googleId: profile.id
      });

      newGoogleUser.save((err) => {
        if(err) console.log(err);
        else {
          User.findOne({googleId: profile.id}, (err, foundedG) => {
            if(err) console.log(err);
            else {return done(null, foundedG)}
          })
        }
      })
    }
  }

});
}
passport.use(new GoogleStrategy(gStrategy, callback));


// it saves the userId into re.session and cookie get set 
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  User.findById(id, (err, user) => {
    done(err, user);
  });
});

app.use(passport.initialize());
app.use(passport.session());

//------------------------- Routs----------------------------------------//
app.get("/", (req, res) => {
  console.log(req.session);
  if (req.isAuthenticated()) {
    res.redirect("/secrets");
  } else {
    res.render("home");
  }
});

app.get('/auth/google', passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // on Successful authentication redireted to secret page
    res.redirect('/secrets');
  });

app.get("/register", (req, res) => {
  if (req.isAuthenticated()) {
    res.redirect("/secrets");
  } else {
    res.render("register");
  }
});

app.get("/login", (req, res) => {
  if (req.isAuthenticated()) {
    res.redirect("/secrets");
  } else {
    res.render("login");
  }
});

app.post("/register", (req, res) => {
  let username = req.body.username;
  let password = req.body.password;
  User.findOne({ username: username }, (err, userFound) => {
    if (!err) {
      if (userFound) res.redirect("/login");
      else {
        let hashpassword = passCreate(password);

        const newUser = new User({
          username: username,
          salt: hashpassword.passsalt,
          hash: hashpassword.passhash,
        });
        newUser.save((err) => {
          if (err) console.log(err);
          else res.redirect("/login");
        });
      }
    }
  });
});

app.post(
  "/login",
  passport.authenticate("local", { failureRedirect: "/register" }),
  (req, res) => {
    res.redirect("/secrets");
  },
);

app.get("/secrets", (req, res) => {
  if (req.isAuthenticated()) {
    User.find({"secret" : {$ne: null}},(err , foundsecret) => {
      if (err) {
        console.log(err);
      }else{
        res.render("secrets", {UserSecret : foundsecret});
      }
    });
  } else res.redirect("/login");
});

app.get("/submit",(req,res)=>{
  if (req.isAuthenticated()) {
    res.render("submit");
  } else res.redirect("/login");
});

app.post("/submit",(req,res)=>{
  const Secret = req.body.secret;
User.findById(req.user.id, (err, foundUser)=>{
  if(err) console.log(err);
else{
  if(foundUser){
  foundUser.secret = Secret;
  foundUser.save(()=>{
    res.redirect("/secrets");
  });
}
}
});

});

app.get("/logout", (req, res) => {
  req.logOut();
  res.redirect("/");
});

//----------------------------------- Connect to server-----------------------
let port = process.env.PORT;
if (port == "" || port == null || port == undefined) {
  port = 3000;
}
app.listen(port, () => {
  console.log(`Server is running on port : ${port}`);
});
