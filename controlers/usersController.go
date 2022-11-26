package controlers

import (
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
	"lionauth.ml/goAuth/initializers"
	"lionauth.ml/goAuth/models"
)

func Signup(c *gin.Context)  {
	//Get the email/password off req body

	var body struct {
		Email		string `json:"email"`
		Password	string `json:"password"`
	}

	err := c.Bind(&body)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to read body",
			"errMessage": err.Error(),
		})
		return
	}

	//Check if user already exists

	var userFind models.User
	initializers.DB.First(&userFind, "email = ?", body.Email)

	if userFind.ID != 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "User with email  " + body.Email + " already exists",
		})
		return
	}

	//Hash the Password

	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 10)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to hash password",
		})
		return
	}

	//Create user
	user := models.User{Email: body.Email, Password: string(hash)}

	result := initializers.DB.Create(&user)

	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create user",
		})
		return
	}

	//Responde
	c.JSON(http.StatusCreated, gin.H{})
}

func Login(c *gin.Context)  {
	//Get the email/password off req body

	var body struct {
		Email		string `json:"email"`
		Password	string `json:"password"`
	}

	err := c.Bind(&body)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to read body",
			"errMessage": err.Error(),
		})
		return
	}

	//Look up requested user
	var user models.User
	initializers.DB.First(&user, "email = ?", body.Email)

	if user.ID == 0 {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Cant find user with email: " + body.Email,
		})
		return
	}

	//Compare passworeds
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password))

	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "Wrong password",
		})
		return
	}

	//Generate jwt
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id": user.ID,
		"email": user.Email,
		"created_at": user.CreatedAt,
		"deleted_at": user.DeletedAt,
		"updated_at": user.UpdatedAt,
		"exp": time.Now().Add(time.Hour * 24 * 30).Unix(),
	})

	tokenString, err := token.SignedString([]byte(os.Getenv("SECERET_KEY")))

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"err": err.Error(),
		})
		return
	}

	//Retrun Cookie
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("Auth", tokenString, 3600*24*30, "", "", false, true)

	//Return JWT
	c.JSON(http.StatusAccepted, gin.H{
		"jwt": tokenString,
	})
}

func Validate(c *gin.Context) {
	user, _ := c.Get("user")

	c.JSON(http.StatusOK, gin.H{
		"message": user,
	})
}