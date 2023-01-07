const express = require("express");
const app = express();
const controller = require("./controller");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const sessions = require("express-session");

const authtoken = (req, res, next) => {
  if (!req.cookies.token) next();
  else {
    console.log(req.session.id);
    if (jwt.verify(req.cookies.token, "secret")) {
      res.render("welcome", {
        message: "Welcome To Our Site ",
        title: "Dashboard",
      });
    }
  }
};

app.use(
  sessions({
    secret: "thisismysecrctekeyfhrgfgrfrty84fwir767",
    saveUninitialized: true,

    resave: false,
  })
);

app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set("view engine", "ejs");

app.get("/", (req, res) => {
  res.render("index", { title: "Home", message: "Home" });
});

app.post("/login", controller.login);
app.get("/login", authtoken, (req, res) => {
  res.render("login", { title: "Login" });
});

app.post("/signup", controller.signup);
app.get("/signup", (req, res) => {
  res.render("signup", { title: "SignUp" });
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  res.clearCookie("token");
  res.redirect("/");
});

app.get("/dashboard", authtoken, (req, res) => {
  res.redirect("/login");
});

module.exports = app;
