import express from "express";
import bodyParser from "body-parser";
import morgan from "morgan";
import 'dotenv/config';
import pg from "pg";
import bcrypt from "bcrypt";
const saltRounds = 12;

const app = express();
const port = 3000;
const {Client} = pg;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(morgan('dev'));

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

app.post("/login", async (req, res) => {
  const {username:email,password:typedPassword} = req.body;
  try {
    //check if email exists:
    const result = await db.query("SELECT password FROM users WHERE email=$1;",[email]);
    if (result.rows.length===0) {
      return res.send("Your email is not register yet. Try to register first.")
    }
    const hash = result.rows[0].password;
    bcrypt.compare(typedPassword,hash, async (err,isMatch) => {
      if (err) {
        return res.status(501).send(`Login error:  ${err.message}`);
      } else {
        if (isMatch) {
          return res.status(200).render("secrets.ejs");  
        } else {
          return res.status(401).send("Incorret password!");
        }
        
      }
    });
  } catch (error) {
    console.log(error)
    return res.status(500).send(error.details)
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
