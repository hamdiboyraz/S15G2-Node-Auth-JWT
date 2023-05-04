const router = require("express").Router();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const { usernameVarmi, rolAdiGecerlimi } = require("./auth-middleware");
const { JWT_SECRET } = require("../secrets"); // bu secret'ı kullanın!
const userModel = require("../users/users-model");

router.post("/register", rolAdiGecerlimi, async (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status: 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
  try {
    let { username, password, role_name } = req.body;
    password = bcrypt.hashSync(password);
    const newUser = await userModel.ekle({ username, password, role_name });
    res.status(201).json(newUser);
  } catch (error) {
    next(error);
  }
});

router.post("/login", usernameVarmi, async (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status: 200
    {
      "message": "sue geri geldi!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    Token 1 gün sonra timeout olmalıdır ve aşağıdaki bilgiyi payloadında içermelidir:

    {
      "subject"  : 1       // giriş yapan kullanıcının user_id'si
      "username" : "bob"   // giriş yapan kullanıcının username'i
      "role_name": "admin" // giriş yapan kulanıcının role adı
    }
   */
  try {
    const { username, password } = req.body;
    const [user] = await userModel.goreBul({ username });
    if (user && bcrypt.compareSync(password, user.password)) {
      const tokenPayload = {
        subject: user.user_id,
        username: user.username,
        role_name: user.role_name,
      };
      const tokenOptions = {
        expiresIn: "1d",
      };
      const token = jwt.sign(tokenPayload, JWT_SECRET, tokenOptions);
      res.status(200).json({ message: `${user.username} geri geldi!`, token });
    } else {
      res.status(401).json({ message: "Geçersiz kriter" });
    }
  } catch (error) {
    next(error);
  }
});

module.exports = router;
