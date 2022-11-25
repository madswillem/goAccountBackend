package main

import (
	"fmt"
	"lionauth.ml/goAuth/initializers"
	"github.com/gin-gonic/gin"
)

func init()  {
	initializers.LoadEnvVariables()
	initializers.ConnectToDB()
}

func main() {
	r := gin.Default()
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})
	r.Run()
	fmt.Println("Hello World")
}