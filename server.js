const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const path = require("path");

const db = require("./database");

const app = express();

const PORT = process.env.PORT || 3000;

const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  throw new Error(
    "JWT_SECRET должен содержать минимум 32 символа."
  );
}

app.use(express.json({ limit: "1mb" }));

function createToken(user) {
  return jwt.sign(
    { id: user.id },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function auth(req, res, next) {
  const token = req.headers.authorization?.replace(
    /^Bearer\s+/i,
    ""
  );

  if (!token) {
    return res.status(401).json({
      error: "Требуется авторизация"
    });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    const user = db.prepare(`
      SELECT id, username, premium, admin
      FROM users
      WHERE id = ?
    `).get(decoded.id);

    if (!user) {
      return res.status(401).json({
        error: "Пользователь не найден"
      });
    }

    req.user = user;
    next();
  } catch {
    res.status(401).json({
      error: "Недействительная сессия"
    });
  }
}

function adminOnly(req, res, next) {
  if (!req.user.admin) {
    return res.status(403).json({
      error: "Доступ запрещён"
    });
  }

  next();
}

function validUsername(username) {
  return (
    typeof username === "string" &&
    /^[a-zA-Zа-яА-ЯёЁ0-9_-]{3,30}$/.test(username)
  );
}

function validPassword(password) {
  return (
    typeof password === "string" &&
    password.length >= 8 &&
    password.length <= 128
  );
}

function publicUser(user) {
  return {
    id: user.id,
    username: user.username,
    premium: !!user.premium,
    admin: !!user.admin
  };
}

/* =========================
   Регистрация
========================= */

app.post("/api/register", (req, res) => {
  const { username, password } = req.body || {};

  if (!validUsername(username) || !validPassword(password)) {
    return res.status(400).json({
      error: "Логин должен содержать 3–30 символов, пароль — 8–128."
    });
  }

  const existing = db.prepare(`
    SELECT id FROM users WHERE username = ?
  `).get(username);

  if (existing) {
    return res.status(409).json({
      error: "Логин уже занят"
    });
  }

  const hash = bcrypt.hashSync(password, 12);

  const result = db.prepare(`
    INSERT INTO users (username, password, premium, admin)
    VALUES (?, ?, 0, 0)
  `).run(username, hash);

  const user = db.prepare(`
    SELECT id, username, premium, admin
    FROM users WHERE id = ?
  `).get(result.lastInsertRowid);

  res.status(201).json({
    token: createToken(user),
    user: publicUser(user)
  });
});

/* =========================
   Вход
========================= */

app.post("/api/login", (req, res) => {
  const { username, password } = req.body || {};

  if (
    typeof username !== "string" ||
    typeof password !== "string"
  ) {
    return res.status(400).json({
      error: "Укажи логин и пароль"
    });
  }

  const user = db.prepare(`
    SELECT * FROM users WHERE username = ?
  `).get(username);

  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({
      error: "Неверный логин или пароль"
    });
  }

  res.json({
    token: createToken(user),
    user: publicUser(user)
  });
});

/* =========================
   Текущий аккаунт
========================= */

app.get("/api/me", auth, (req, res) => {
  res.json(publicUser(req.user));
});

/* =========================
   Получение привычек
========================= */

app.get("/api/habits", auth, (req, res) => {
  const rows = db.prepare(`
    SELECT *
    FROM habits
    WHERE user_id = ?
    ORDER BY rowid DESC
  `).all(req.user.id);

  const getDays = db.prepare(`
    SELECT date
    FROM habit_days
    WHERE habit_id = ? AND completed = 1
  `);

  const habits = rows.map(habit => {
    const days = {};

    for (const row of getDays.all(habit.id)) {
      days[row.date] = true;
    }

    return {
      id: habit.id,
      name: habit.name,
      description: habit.description,
      type: habit.type,
      emoji: habit.emoji,
      createdAt: habit.created_at,
      days
    };
  });

  res.json(habits);
});

/* =========================
   Создание привычки
========================= */

app.post("/api/habits", auth, (req, res) => {
  const {
    name,
    description = "",
    type,
    emoji = ""
  } = req.body || {};

  if (
    typeof name !== "string" ||
    !name.trim() ||
    name.length > 70 ||
    !["good", "bad"].includes(type) ||
    typeof description !== "string" ||
    description.length > 1000 ||
    typeof emoji !== "string" ||
    emoji.length > 32
  ) {
    return res.status(400).json({
      error: "Некорректные данные привычки"
    });
  }

  const id = crypto.randomUUID();

  const createdAt = new Date().toLocaleDateString("en-CA");

  db.prepare(`
    INSERT INTO habits (
      id,
      user_id,
      name,
      description,
      type,
      emoji,
      created_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(
    id,
    req.user.id,
    name.trim(),
    description.trim(),
    type,
    emoji || (type === "bad" ? "🚫" : "✨"),
    createdAt
  );

  res.status(201).json({ id });
});

/* =========================
   Редактирование привычки
========================= */

app.put("/api/habits/:id", auth, (req, res) => {
  const habit = db.prepare(`
    SELECT id FROM habits
    WHERE id = ? AND user_id = ?
  `).get(req.params.id, req.user.id);

  if (!habit) {
    return res.status(404).json({
      error: "Привычка не найдена"
    });
  }

  const {
    name,
    description = "",
    type,
    emoji = ""
  } = req.body || {};

  if (
    typeof name !== "string" ||
    !name.trim() ||
    name.length > 70 ||
    !["good", "bad"].includes(type) ||
    typeof description !== "string" ||
    description.length > 1000 ||
    typeof emoji !== "string" ||
    emoji.length > 32
  ) {
    return res.status(400).json({
      error: "Некорректные данные"
    });
  }

  db.prepare(`
    UPDATE habits
    SET name = ?, description = ?, type = ?, emoji = ?
    WHERE id = ? AND user_id = ?
  `).run(
    name.trim(),
    description.trim(),
    type,
    emoji || (type === "bad" ? "🚫" : "✨"),
    req.params.id,
    req.user.id
  );

  res.json({ success: true });
});

/* =========================
   Удаление привычки
========================= */

app.delete("/api/habits/:id", auth, (req, res) => {
  const result = db.prepare(`
    DELETE FROM habits
    WHERE id = ? AND user_id = ?
  `).run(req.params.id, req.user.id);

  if (!result.changes) {
    return res.status(404).json({
      error: "Привычка не найдена"
    });
  }

  res.json({ success: true });
});

/* =========================
   Отметка выполнения
========================= */

app.put("/api/habits/:id/days/:date", auth, (req, res) => {
  const { id, date } = req.params;

  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
    return res.status(400).json({
      error: "Некорректная дата"
    });
  }

  const habit = db.prepare(`
    SELECT id FROM habits
    WHERE id = ? AND user_id = ?
  `).get(id, req.user.id);

  if (!habit) {
    return res.status(404).json({
      error: "Привычка не найдена"
    });
  }

  const completed = req.body?.completed === true;

  if (completed) {
    db.prepare(`
      INSERT INTO habit_days (habit_id, date, completed)
      VALUES (?, ?, 1)
      ON CONFLICT(habit_id, date)
      DO UPDATE SET completed = 1
    `).run(id, date);
  } else {
    db.prepare(`
      DELETE FROM habit_days
      WHERE habit_id = ? AND date = ?
    `).run(id, date);
  }

  res.json({ success: true });
});

/* =========================
   Админ-панель
========================= */

app.get(
  "/api/admin/users",
  auth,
  adminOnly,
  (req, res) => {
    const users = db.prepare(`
      SELECT id, username, premium, admin, created_at
      FROM users
      ORDER BY username
    `).all();

    res.json(users);
  }
);

/* Создание Premium-аккаунта */

app.post(
  "/api/admin/users",
  auth,
  adminOnly,
  (req, res) => {
    const { username, password } = req.body || {};

    if (
      !validUsername(username) ||
      !validPassword(password)
    ) {
      return res.status(400).json({
        error: "Некорректный логин или пароль"
      });
    }

    const existing = db.prepare(`
      SELECT id FROM users WHERE username = ?
    `).get(username);

    if (existing) {
      return res.status(409).json({
        error: "Логин занят"
      });
    }

    const hash = bcrypt.hashSync(password, 12);

    db.prepare(`
      INSERT INTO users (
        username,
        password,
        premium,
        admin
      )
      VALUES (?, ?, 1, 0)
    `).run(username, hash);

    res.status(201).json({
      success: true
    });
  }
);

/* Выдача и отзыв Premium */

app.patch(
  "/api/admin/users/:id/premium",
  auth,
  adminOnly,
  (req, res) => {
    const id = Number(req.params.id);

    const user = db.prepare(`
      SELECT id, admin FROM users WHERE id = ?
    `).get(id);

    if (!user) {
      return res.status(404).json({
        error: "Пользователь не найден"
      });
    }

    if (user.admin) {
      return res.status(403).json({
        error: "Нельзя изменить Premium администратора"
      });
    }

    db.prepare(`
      UPDATE users SET premium = ?
      WHERE id = ?
    `).run(req.body?.premium === true ? 1 : 0, id);

    res.json({ success: true });
  }
);

/* Удаление пользователя */

app.delete(
  "/api/admin/users/:id",
  auth,
  adminOnly,
  (req, res) => {
    const id = Number(req.params.id);

    const user = db.prepare(`
      SELECT id, admin FROM users WHERE id = ?
    `).get(id);

    if (!user) {
      return res.status(404).json({
        error: "Пользователь не найден"
      });
    }

    if (user.admin) {
      return res.status(403).json({
        error: "Нельзя удалить администратора"
      });
    }

    db.prepare(`
      DELETE FROM users WHERE id = ?
    `).run(id);

    res.json({ success: true });
  }
);

/* =========================
   Сайт
========================= */

app.use(express.static(__dirname));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Сервер запущен на порту ${PORT}`);
});