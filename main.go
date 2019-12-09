package main

import (
	"issues/controller"
	"issues/model"

	"github.com/gin-gonic/contrib/jwt"

	"github.com/gin-gonic/gin"
)

func main() {
	router := gin.Default()
	ginController := controller.NewController()

	config := model.SetupConfig()
	db := model.ConnectDb(config.Database.User, config.Database.Password, config.Database.Database, config.Database.Address)
	defer db.Close()

	ginController.DB = db
	ginController.Config = config

	//router.POST("/signup", ginController.Register)
	//router.POST("/register", ginController.RegisterJSON)

	// router.POST("/login", ginController.Login)
	router.POST("/login", ginController.LoginJSON)

	router.GET("/issues", ginController.ListIssues)

	router.GET("/profile", jwt.Auth(model.SecretKey), ginController.GetProfile)

	router.GET("/get-user", jwt.Auth(model.SecretKey), ginController.GetUser)

	router.GET("/get-manager", jwt.Auth(model.SecretKey), ginController.GetManager)

	router.PUT("/insert-user", jwt.Auth(model.SecretKey), ginController.InsertUser)

	router.PUT("/insert-issues", jwt.Auth(model.SecretKey), ginController.InsertIssues)

	//router.GET("/test", jwt.Auth(model.SecretKey), Controller.tokenGenerate)

	/* router.GET("/issues/:id", jwt.Auth(model.SecretKey), ginController.IssueDetail)
	router.POST("/create-issue", jwt.Auth(model.SecretKey), ginController.CreateIssue)

	router.GET("/profile", jwt.Auth(model.SecretKey), ginController.ProfileDetail)

	router.POST("/upload-file", jwt.Auth(model.SecretKey), ginController.UploadFile)

	router.GET("/media/static/:userId/:fileId", jwt.Auth(model.SecretKey), ginController.ServeFile)
	*/

	router.Run(":8088")

}
