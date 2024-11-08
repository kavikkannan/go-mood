package main

import (
	/* "log"
	"net/http" */
	"log"

	"github.com/gofiber/fiber/v2"
	/* "github.com/rs/cors" */
	"github.com/gofiber/fiber/v2/middleware/cors"
	_ "github.com/jinzhu/gorm/dialects/mysql"
	"github.com/kavikkannan/go-mood/pkg/config"
	"github.com/kavikkannan/go-mood/pkg/routes"
	

	"database/sql"


	_ "github.com/mattn/go-sqlite3"
)

func main() {
	InitDB()
    config.Connect()
	app := fiber.New()
	app.Use(cors.New(cors.Config{
		AllowCredentials: true,
		AllowOrigins:     "http://localhost:3000", // Use "http" if your frontend is on HTTP
	}))
	routes.Setup(app)

	
	app.Listen(":9000")
}


var db *sql.DB

func InitDB() {
	


    var err error
    db, err = sql.Open("sqlite3", "./mood.db")
    if err != nil {
        log.Fatal("failed to connect to database:", err)
    }
	defer db.Close()
}
