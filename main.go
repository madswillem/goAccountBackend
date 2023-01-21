package main

import (
	"github.com/gin-gonic/gin"
	"lionauth.ml/goAuth/initializers"
	"lionauth.ml/goAuth/middleware"
	"lionauth.ml/goAuth/controllers"
)

func init()  {
	initializers.LoadEnvVariables()
	initializers.ConnectToDB()
}

func main() {
	r := gin.Default()
	r.POST("/signup", controllers.Signup)
	r.POST("/login", controllers.Login)
	r.GET("/validate", middleware.RequireAuth,  controllers.Validate)
	r.Run()
}