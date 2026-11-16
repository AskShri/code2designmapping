package main

import "github.com/gin-gonic/gin"

func main() {
	r := gin.Default()
	api := r.Group("/api", AuthMiddleware())
	api.GET("/me", func(c *gin.Context) {})
	r.GET("/ping", func(c *gin.Context) {})
	r.Run()
}
