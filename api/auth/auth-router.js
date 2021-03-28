const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const model = require("../../api/users/users-model")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")


  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
router.post("/register", validateRoleName, async (req, res, next) => {
    
  try {
  const { username, password, role_name } = req.body
    const user = await model.findBy(username)

    if (user){
      return res.status(409).json({
        message: "Username is already taken",
      })
    }

  const newUser = await model.add({
    username,
    password: await bcrypt.hash(password, 5),
    role_name,

  })

  res.status(201).json(newUser)

 } catch(err){
      next(err)
  }

});



  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */

router.post("/login", checkUsernameExists, async (req, res, next) => {
   
  try {
    const { username, password } = req.body
    const user = await model.findBy(username)


    // hash the password again and see if it matches what we have in the database
		const passwordValid = await bcrypt.compare(password, user.password)

    if (!passwordValid) {
			return res.status(401).json({
				message: "Invalid Credentials",
			})
		}

    const token = jwt.sign({
           
           userID: user.user_id,
           user_Role: user.role_name,
    }, JWT_SECRET)

    res.json({
      message: `Welcome ${user.username}!`,
      token: token,
    })

  } catch (err){
    next(err)
  }


});

module.exports = router;
