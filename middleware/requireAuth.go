package middleware

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"lionauth.ml/goAuth/models"
)

func RequireAuth(c *gin.Context) {
	//Get Cookie || Get bearer

	//Cookie;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	tokenString, err := c.Cookie("Auth")

	//Bearer;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	if err != nil || tokenString == "" {
		authHeader := c.GetHeader("Authorization")

		// Authorization header is missing in HTTP request
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "No Authheader" + authHeader,
			})
			return
		}

		authTokens := strings.Split(authHeader, " ")

		// The value of authorization header is invalid
		// It should start with "Bearer ", then the token value
		if len(authTokens) != 2 || authTokens[0] != "Bearer" {
			if len(authTokens) != 2 {
				c.JSON(http.StatusUnauthorized, gin.H{
					"error": "No real auth Header",
				})
				return
			} else {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error": "Wrong Auuth Header",
				})
				return
			}
		}

		tokenString = authTokens[1]
	}

	if tokenString == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "No auth " + err.Error() + tokenString,
		})
		return
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
			return
		}

		//Bind token Values to usermodel
		var user models.User

		user.ID = uint(claims["id"].(float64))
		user.Email = claims["email"].(string)

		//CreatedAt
		fmt.Println(claims["created_at"].(string))
		date, err := time.Parse("2006-01-02T15:04:05.999999999+01:00", claims["created_at"].(string))
  
		if err != nil {
			fmt.Println(err)
			return
		}

		fmt.Println(date)

		user.CreatedAt = date

		//UpdatedAt
		fmt.Println(claims["created_at"].(string))
		date, err = time.Parse("2006-01-02T15:04:05.999999999+01:00", claims["updated_at"].(string))
  
		if err != nil {
			fmt.Println(err)
			return
		}

		fmt.Println(date)

		user.UpdatedAt = date

		//Atach to req
		c.Set("user", user)

	} else {
		fmt.Println(err)
	}

	c.Next()
}
