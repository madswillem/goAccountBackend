package main

import (
	"github.com/gin-gonic/gin"
	"lionauth.ml/goAuth/controlers"
	"lionauth.ml/goAuth/initializers"
)

func init()  {
	initializers.LoadEnvVariables()
	initializers.ConnectToDB()
}

func main() {
	r := gin.Default()
	r.POST("/signup", controlers.Signup)
	r.POST("/login", controlers.Login)
	r.Run()
}