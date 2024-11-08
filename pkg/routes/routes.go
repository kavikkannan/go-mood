package routes

import (
	"github.com/gofiber/fiber/v2"
	"github.com/kavikkannan/go-mood/pkg/controllers"
	"github.com/kavikkannan/go-mood/pkg/middleware"
)

func Setup(app *fiber.App) {

	app.Post("/api/register", controllers.Register)
	app.Post("/api/login", controllers.Login)
	app.Get("/api/user", controllers.User)
	app.Post("/api/logout", controllers.Logout)

	app.Post("/api/submit_mood", controllers.SubmitMood)
	app.Get("/api/get_mood_log", controllers.GetMoodLog)
	app.Post("/api/set_waking_hours", controllers.SetWakingHours)
	

}
