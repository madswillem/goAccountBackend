package middleware

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"lionauth.ml/goAuth/models"
)

func RequireAuth(c *gin.Context) {
	//Get Cookie
	tokenString, err := c.Cookie("Auth")

	if err != nil {
		c.AbortWithStatus(http.StatusBadRequest)
	}

	//Decode/Validate jwt
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return []byte(os.Getenv("SECERET_KEY")), nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		//Checkb the exp
		if float64(time.Now().Unix()) > claims["exp"].(float64) {
			c.JSON(http.StatusUnauthorized, gin.H{
				"err": "token is expired",
			})
		}

		//Bind token Values to usermodel
		var user models.User

		var id uint = claims["id"].(uint)

		user.ID = id
		user.Email = claims["email"].(string)

		//Atach to req
		c.Set("user", user)

	} else {
		fmt.Println(err)
	}

	c.Next()
}
