import express from "express";
import bodyParser from "body-parser";
import morgan from "morgan";
import 'dotenv/config';
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
const saltRounds = 12;

const app = express();
const port = 3000;
const {Client} = pg;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(morgan('dev'));
//set session and passport
app.use(session({
  secret: 'SUPERTOPSECRET',
  resave:false,
  saveUninitialized: true
}));
app.use(passport.initialize());
app.use(passport.session());

const db = new Client ({
  user: 'postgres',
  host: 'localhost',
  port: 5432,
  password: process.env.db_pwd,
  database: 'secrets'
});

await db.connect();

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/secrets",(req,res)=>{
  console.log(req.user)
  if(req.isAuthenticated()){
    res.render("secrets.ejs")
  } else {
    res.render("login.ejs")
  }
})

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
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
        const query = "INSERT INTO users (email,password) VALUES ($1,$2) RETURNING id";
        const result = await db.query(query,[email,hash]);
        console.log(result.rows[0].id);
        res.render("secrets.ejs");
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

passport.use(new Strategy(async function verify (username, password, cb){
  console.log(username);
  console.log(password);

  try {
    //check if email exists:
    const result = await db.query("SELECT password FROM users WHERE email=$1;",[username]);
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

passport.serializeUser(function (user,cb){
  cb(null,user)
});

passport.deserializeUser(function (user,cb){
  cb(null,user)
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
