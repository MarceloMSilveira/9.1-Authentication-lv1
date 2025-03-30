import express from "express";
import bodyParser from "body-parser";
import morgan from "morgan";
import 'dotenv/config';
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2"
const saltRounds = 12;

const app = express();
const port = 3000;
const {Client} = pg;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(morgan('dev'));
//set session and passport
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave:false,
  saveUninitialized: true,
  cookie: {
    maxAge: 1000*60*15
  }
}));
app.use(passport.initialize());
app.use(passport.session());

const db = new Client ({
  user: 'postgres',
  host: 'localhost',
  port: 5432,
  password: process.env.DB_PWD,
  database: 'secrets'
});

await db.connect();

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/secrets", (req, res) => {
  if (req.isAuthenticated()) {
    const secret = req.user.secret ? req.user.secret : "";  
    res.render("secrets.ejs", {secret: secret});
    //TODO: Update this to pull in the user secret to render in secrets.ejs
  } else {
    res.redirect("/login");
  }
});

//TODO: Add a get route for the submit button
//Think about how the logic should work with authentication.
app.get("/submit", (req,res)=>{
  if (req.isAuthenticated()) {
    res.render("submit.ejs") 
  } else {
    res.redirect("/login")
  }
})

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/auth/google", passport.authenticate("google", {
  scope: ["profile", "email"]
}));

app.get("/auth/google/secrets", passport.authenticate("google", {
  successRedirect: "/secrets",
  failureRedirect: "/login  "
}));

app.get("/logout", function(req, res, next) {
  req.logout(function(err) {
    if (err) { return next(err); }
    res.redirect('/');
  });
});

app.post("/register", async (req, res) => {
  const {username:email,password} = req.body;
  try {
    const checkEmail = await db.query("SELECT * FROM users WHERE email=$1",[email]);
    
    if (checkEmail.rows.length>0) {
      return res.send("Email already exists. Try logging in.");
    } 
    bcrypt.hash(password, saltRounds, async function(err, hash) {
      if (err) {
        console.log('Error in hashing password: ',err);
        res.status(500).send(err);
      } else {
        // Store hash in your password DB.
        const query = "INSERT INTO users (email,password) VALUES ($1,$2) RETURNING *";
        const result = await db.query(query,[email,hash]);
        console.log(result.rows[0]);
        const user = result.rows[0];
        req.login(user,(err)=>{
          console.log(err);
          res.redirect("/submit");
        })
      }
    });
  } catch (error) {
    console.log(error);
    res.status(500).send(error);
  }
});

app.post("/login", passport.authenticate("local", {
  successRedirect:"/secrets",
  failureRedirect:"/login"
}));

//TODO: Create the post route for submit.
//Handle the submitted data and add it to the database
app.post("/submit", async (req,res)=>{
  const secret = req.body.secret;
  const email = req.user.email;
  try {
    const query = "UPDATE users SET secret = $1 WHERE email = $2 RETURNING *";
        const result = await db.query(query,[secret,email]);
        const user = result.rows[0];
        console.log(user);
        if (result.rows.length === 0) {
          console.log("User not found.");
          return res.redirect("/login");
        }
        req.login(user,(err)=>{
         if (err) {
           console.log("Error in login:", err);
         }
         return res.redirect("/secrets");
        })
  } catch (error) {
    console.log(error);
    return res.render("home.ejs");
  }
})

passport.use("local",new Strategy(async function verify (username, password, cb){
  //console.log(username);
  //console.log(password);

  try {
    //check if email exists:
    const result = await db.query("SELECT * FROM users WHERE email=$1;",[username]);
    if (result.rows.length===0) {
      return cb("Your email is not register yet. Try to register first.")
    }
    const user = result.rows[0];
    const hash = result.rows[0].password;
    bcrypt.compare(password,hash, async (err,isMatch) => {
      if (err) {
        return cb(err);
      } else {
        if (isMatch) {
          return cb(null,user);  
        } else {
          return cb(null,false)
        }
      }
    });
  } catch (error) {
    cb(error)
  }
}))

passport.use("google", new GoogleStrategy({
  clientID:     process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/secrets",
  userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},
async (request, accessToken, refreshToken, profile, cb) => {
  console.log(profile.emails[0].value);
  const email = profile.emails[0].value;
  try {
    const result = await db.query("SELECT * FROM users WHERE email=$1;",[email]);
    if (result.rows.length === 0) {
      const query = "INSERT INTO users (email,password) VALUES ($1,$2) RETURNING *";
      const resultInsert = await db.query(query,[email,"google"]);
      return cb(null,resultInsert.rows[0]);
    } else {
      return cb(null,result.rows[0]);
    }
  } catch (error) {
    return cb(error)
  }
}
))

passport.serializeUser(function (user,cb){
  cb(null,user)
});

passport.deserializeUser(function (user,cb){
  cb(null,user)
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
