const express = require("express");
const mongoose = require("mongoose");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const methodOverride = require("method-override");
const expressLayouts = require("express-ejs-layouts");
const bcrypt = require("bcryptjs");
const User = require("./models/user");
const Post = require("./models/post");
const app = express();

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(methodOverride("_method"));
app.use(expressLayouts);
app.set("view engine", "ejs");
app.set("layout", "layout"); // layout.ejs is the base template

// Session
app.use(
  session({
    secret: "secretkey",
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: "mongodb://127.0.0.1:27017/blogDB" }),
  })
);

// Flash middleware (for errors/notifications)
app.use((req, res, next) => {
  res.locals.error = req.session.error || null;
  delete req.session.error;
  next();
});

// ---------------------- MIDDLEWARE ----------------------
function requireLogin(req, res, next) {
  if (!req.session.userId) {
    req.session.error = "Please login first.";
    return res.redirect("/login");
  }
  next();
}

// Make user available in EJS
app.use(async (req, res, next) => {
  if (req.session.userId) {
    res.locals.user = await User.findById(req.session.userId);
  } else {
    res.locals.user = null;
  }
  next();
});

// ---------------------- ROUTES ----------------------

// Home (list posts with search)
app.get("/", async (req, res) => {
  const search = req.query.search || "";

  // Fetch posts with author populated
  let posts = await Post.find().populate("author");

  if (search) {
    const regex = new RegExp(search, "i"); // case-insensitive

    // Filter posts manually by title, category, or author.username
    posts = posts.filter(post =>
      regex.test(post.title) ||
      regex.test(post.category) ||
      (post.author && regex.test(post.author.username))
    );
  }

  res.render("index", { posts, search });
});


// Signup
app.get("/signup", (req, res) => {
  res.render("signup");
});

app.post("/signup", async (req, res) => {
  const { username, email, password } = req.body;

  // check if email already exists
  const existing = await User.findOne({ email });
  if (existing) {
    req.session.error = "Account already exists with this email.";
    return res.redirect("/signup");
  }

  const hashed = await bcrypt.hash(password, 10);
  await User.create({ username, email, password: hashed });
  req.session.error = "Signup successful! Please login.";
  res.redirect("/login");
});

// Login
app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });

  if (!user) {
    req.session.error = "User not found. Please sign up.";
    return res.redirect("/signup");
  }

  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    req.session.error = "Wrong password!";
    return res.redirect("/login");
  }

  req.session.userId = user._id;
  res.redirect("/");
});

// Logout
app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/");
  });
});

// Create post
app.get("/create", requireLogin, (req, res) => {
  res.render("createPost");
});

app.post("/create", requireLogin, async (req, res) => {
  const { title, content, category } = req.body;
  await Post.create({ title, content, category, author: req.session.userId });
  res.redirect("/");
});

// Post details
app.get("/post/:id", async (req, res) => {
  const post = await Post.findById(req.params.id).populate("author");
  if (!post) {
    req.session.error = "Post not found.";
    return res.redirect("/");
  }
  res.render("postDetails", { post });
});

// Edit post
app.get("/edit/:id", requireLogin, async (req, res) => {
  const post = await Post.findById(req.params.id);
  if (!post) {
    req.session.error = "Post not found.";
    return res.redirect("/");
  }

  if (
    post.author.toString() !== req.session.userId &&
    res.locals.user.role !== "admin"
  ) {
    req.session.error = "Not allowed.";
    return res.redirect("/");
  }
  res.render("editPost", { post });
});

app.post("/edit/:id", requireLogin, async (req, res) => {
  const post = await Post.findById(req.params.id);
  if (!post) {
    req.session.error = "Post not found.";
    return res.redirect("/");
  }

  if (
    post.author.toString() !== req.session.userId &&
    res.locals.user.role !== "admin"
  ) {
    req.session.error = "Not allowed.";
    return res.redirect("/");
  }

  const { title, content, category } = req.body;
  post.title = title;
  post.content = content;
  post.category = category;
  await post.save();

  res.redirect("/post/" + req.params.id);
});

// Delete post
app.post("/delete/:id", requireLogin, async (req, res) => {
  const post = await Post.findById(req.params.id);
  if (!post) {
    req.session.error = "Post not found.";
    return res.redirect("/");
  }

  if (
    post.author.toString() !== req.session.userId &&
    res.locals.user.role !== "admin"
  ) {
    req.session.error = "Not allowed.";
    return res.redirect("/");
  }

  await Post.findByIdAndDelete(req.params.id);
  res.redirect("/");
});

// Profile route (show logged-in user's posts)
app.get("/profile", requireLogin, async (req, res) => {
  const user = await User.findById(req.session.userId);
  if (!user) return res.redirect("/login");

  const posts = await Post.find({ author: user._id }).sort({ createdAt: -1 });
  res.render("profile", { user, posts });
});

// ---------------------- DB + SERVER ----------------------
mongoose
  .connect("mongodb://127.0.0.1:27017/blogDB")
  .then(() =>
    app.listen(3000, () =>
      console.log("Server running on http://localhost:3000")
    )
  )
  .catch((err) => console.log(err));
