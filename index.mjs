import express from "express";
import path from "node:path";
import url from "node:url";
import passport from "passport";
import LocalStrategy from "passport-local";
import GitHubStrategy from "passport-github2";
import bcrypt from "bcrypt";
import session from "express-session";

const app = express();
const PORT = 3000;

const USERS = [];

const __filename = url.fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

passport.use(
  new LocalStrategy((username, password, done) => {
    const user = USERS.find((u) => u.username === username);
    if (!user) return done(null, false, { message: "Incorrect username." });
    bcrypt.compare(password, user.password, (err, res) => {
      if (res) return done(null, user);
      else return done(null, false, { message: "Incorrect password." });
    });
  })
);

passport.use(
  new GitHubStrategy(
    {
      clientID: "Ov23liZMosCtUoGEmSte",
      clientSecret: "c48d6cc0491646f5d905a6bbe7ae2eb7bada5764",
      callbackURL: "http://localhost:3000/auth/github/callback",
    },
    (accessToken, refreshToken, profile, done) => {
      let user = USERS.find((u) => u.githubId === profile.id);
      if (!user) {
        user = { githubId: profile.id, username: profile.username };
        USERS.push(user);
      }
      return done(null, user);
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user.username);
});

passport.deserializeUser((username, done) => {
  const user = USERS.find((u) => u.username === username);
  done(null, user);
});

// view engine setup
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

app.use(express.urlencoded({ extended: false }));
app.use(
  session({
    secret: "your_secret_key",
    resave: false,
    saveUninitialized: true,
  })
);
app.use(passport.initialize());
app.use(passport.session());

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect("/login");
}

function redirectIfAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return res.redirect("/dashboard");
  }
  next();
}

app.get("/", (req, res) => {
  return res.send("Hello there!");
});

// Signup

app.get("/signup", redirectIfAuthenticated, (req, res) => {
  res.render("signup");
});

app.post("/signup", (req, res) => {
  const { username, password } = req.body;
  const saltRounds = 10;
  bcrypt.hash(password, saltRounds, (err, hash) => {
    if (err) {
      return res.status(500).send("Error hashing password.");
    }
    USERS.push({ username, password: hash });
    res.redirect("/login");
  });
});

// Login

app.get("/login", redirectIfAuthenticated, (req, res) => {
  res.render("login");
});

app.post(
  "/login/password",
  passport.authenticate("local", {
    successRedirect: "/dashboard",
    failureRedirect: "/login",
  })
);

// GitHub Auth
app.get(
  "/auth/github",
  passport.authenticate("github", { scope: ["user:email"] })
);

app.get(
  "/auth/github/callback",
  passport.authenticate("github", { failureRedirect: "/login" }),
  (req, res) => {
    res.redirect("/dashboard");
  }
);

// Dashboard and Logout

app.get("/dashboard", ensureAuthenticated, (req, res) => {
  res.render("dashboard");
});

app.post("/signout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/login");
  });
});

app.listen(PORT);
