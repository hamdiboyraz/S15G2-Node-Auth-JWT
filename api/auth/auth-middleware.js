const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { JWT_SECRET } = require("../secrets"); // bu secreti kullanın!
const userModel = require("../users/users-model");

const sinirli = (req, res, next) => {
  /*
    Eğer Authorization header'ında bir token sağlanmamışsa:
    status: 401
    {
      "message": "Token gereklidir"
    }

    Eğer token doğrulanamıyorsa:
    status: 401
    {
      "message": "Token gecersizdir"
    }

    Alt akıştaki middlewarelar için hayatı kolaylaştırmak için kodu çözülmüş tokeni req nesnesine koyun!
  */
  const token = req.headers.authorization;
  if (!token) {
    return res.status(401).json({ message: "Token gereklidir" });
  }
  // OPT 1
  // jwt.verify(token, JWT_SECRET, (err, decodedToken) => {
  //   if (err) {
  //     return res.status(401).json({ message: "Token gecersizdir" });
  //   }

  //   req.decodedToken = decodedToken;
  //   next();
  // });
  // OPT 2
  try {
    const decodedToken = jwt.verify(token, JWT_SECRET);
    req.decodedToken = decodedToken;
    next();
  } catch (err) {
    res.status(401).json({ message: "Token gecersizdir" });
  }
};

const sadece = (role_name) => (req, res, next) => {
  /*
    
	Kullanıcı, Authorization headerında, kendi payloadu içinde bu fonksiyona bağımsız değişken olarak iletilen 
	rol_adı ile eşleşen bir role_name ile bir token sağlamazsa:
    status: 403
    {
      "message": "Bu, senin için değil"
    }

    Tekrar authorize etmekten kaçınmak için kodu çözülmüş tokeni req nesnesinden çekin!
  */
  const userRole = req.decodedToken.role_name;

  if (userRole !== role_name) {
    return res.status(403).json({ message: "Bu, senin için değil" });
  }

  next();
};

const usernameVarmi = async (req, res, next) => {
  /*
    req.body de verilen username veritabanında yoksa
    status: 401
    {
      "message": "Geçersiz kriter"
    }
  */

  try {
    const { username } = req.body;
    const [user] = await userModel.goreBul({ username });

    if (!user) {
      return res.status(401).json({ message: "Geçersiz kriter" });
    }

    // req.user = user;

    next();
  } catch (error) {
    next(error);
  }
};

const rolAdiGecerlimi = (req, res, next) => {
  /*
    Bodydeki role_name geçerliyse, req.role_name öğesini trimleyin ve devam edin.

    Req.body'de role_name eksikse veya trimden sonra sadece boş bir string kaldıysa,
    req.role_name öğesini "student" olarak ayarlayın ve isteğin devam etmesine izin verin.

    Stringi trimledikten sonra kalan role_name 'admin' ise:
    status: 422
    {
      "message": "Rol adı admin olamaz"
    }

    Trimden sonra rol adı 32 karakterden fazlaysa:
    status: 422
    {
      "message": "rol adı 32 karakterden fazla olamaz"
    }
  */
  const { role_name } = req.body;

  if (!role_name || role_name.trim() === "") {
    req.body.role_name = "student";
    return next();
  }

  const trimmedRoleName = role_name.trim();

  if (trimmedRoleName === "admin") {
    return res.status(422).json({ message: "Rol adı admin olamaz" });
  }

  if (trimmedRoleName.length > 32) {
    return res
      .status(422)
      .json({ message: "rol adı 32 karakterden fazla olamaz" });
  }

  req.body.role_name = trimmedRoleName;
  next();
};

module.exports = {
  sinirli,
  usernameVarmi,
  rolAdiGecerlimi,
  sadece,
};
