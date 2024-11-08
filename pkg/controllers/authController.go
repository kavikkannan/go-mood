package controllers

import (
	"database/sql"
	"github.com/dgrijalva/jwt-go"
	"github.com/gofiber/fiber/v2"
	"github.com/kavikkannan/go-mood/pkg/config"
	"golang.org/x/crypto/bcrypt"
	"strconv"

	"time"
	"fmt"
)

const SecretKey = "secret"

// Register a new user
func Register(c *fiber.Ctx) error {
	var data map[string]string
	if err := c.BodyParser(&data); err != nil {
		return err
	}

	password, _ := bcrypt.GenerateFromPassword([]byte(data["password"]), 14)
	

	_, err := config.DB.Exec("INSERT INTO Login (name, email, password) VALUES (?, ?, ?)", data["name"], data["email"], password)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Failed to register user"})
	}

	return c.JSON(fiber.Map{"message": "User registered successfully"})
}

// Login an existing user
func Login(c *fiber.Ctx) error {
	var data map[string]string
	if err := c.BodyParser(&data); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": "Invalid input data"})
	}

	var id int
	var hashedPassword []byte

	// Query to retrieve user information
	err := config.DB.QueryRow("SELECT id, password FROM Login WHERE email = ?", data["email"]).Scan(&id, &hashedPassword)
	if err == sql.ErrNoRows {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"message": "User not found"})
	} else if err != nil {
		fmt.Println("Database error:", err) // Log error for debugging
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Database error"})
	}

	// Check password
	if err := bcrypt.CompareHashAndPassword(hashedPassword, []byte(data["password"])); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": "Incorrect password"})
	}

	// Create JWT claims
	claims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"Issuer":  strconv.Itoa(id),
		"Expires": time.Now().Add(time.Hour * 24).Unix(),
	})
	token, err := claims.SignedString([]byte(SecretKey))
	if err != nil {
		fmt.Println("JWT signing error:", err) // Log JWT error for debugging
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Could not login"})
	}

	// Set cookie
	cookie := fiber.Cookie{
		Name:     "jwt",
		Value:    token,
		Expires:  time.Now().Add(time.Hour * 24),
		HTTPOnly: true,
		SameSite: "None",
	}
	if c.Protocol() == "https" {
		cookie.Secure = true
	}
	c.Cookie(&cookie)

	return c.JSON(fiber.Map{"message": "Login successful"})
}

// Get User details based on JWT
func User(c *fiber.Ctx) error {
	cookie := c.Cookies("jwt")

	token, err := jwt.ParseWithClaims(cookie, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(SecretKey), nil
	})
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"message": "Unauthenticated"})
	}
	claims := token.Claims.(*jwt.StandardClaims)

	var Login struct {
		ID       int
		Name     string
		Email    string
		IsAdmin  bool
	}
	err = config.DB.QueryRow("SELECT id, name, email, is_admin FROM Login WHERE id = ?", claims.Issuer).Scan(&Login.ID, &Login.Name, &Login.Email, &Login.IsAdmin)
	if err == sql.ErrNoRows {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"message": "User not found"})
	} else if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Database error"})
	}

	return c.JSON(Login)
}

// Logout by clearing JWT cookie
func Logout(c *fiber.Ctx) error {
	cookie := fiber.Cookie{
		Name:     "jwt",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HTTPOnly: true,
		SameSite: "None",
	}
	c.Cookie(&cookie)
	return c.JSON(fiber.Map{"message": "Logged out successfully"})
}

func SubmitMood(c *fiber.Ctx) error {
	var data map[string]interface{}
	if err := c.BodyParser(&data); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": "Cannot parse JSON"})
	}

	userId := c.Params("userId") // Retrieve userId from the URL parameter

	query := "INSERT INTO MoodLogs (userId, mood, activity, people) VALUES (?, ?, ?, ?)"
	_, err := config.DB.Exec(query, userId, data["mood"], data["activity"], data["people"])
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Failed to log mood"})
	}

	return c.JSON(fiber.Map{"message": "Mood logged successfully"})
}

func GetMoodLog(c *fiber.Ctx) error {
	userId := c.Params("userId") // Retrieve userId from the URL parameter
	period := c.Query("period", "day") // Default to "day" if period is not specified
	var query string

	switch period {
	case "week":
		query = "SELECT * FROM MoodLogs WHERE userId = ? AND timestamp >= datetime('now', '-7 days') ORDER BY timestamp DESC"
	case "month":
		query = "SELECT * FROM MoodLogs WHERE userId = ? AND timestamp >= datetime('now', '-1 month') ORDER BY timestamp DESC"
	default: // "day" or any other case defaults to last 24 hours
		query = "SELECT * FROM MoodLogs WHERE userId = ? AND timestamp >= datetime('now', '-1 day') ORDER BY timestamp DESC"
	}

	rows, err := config.DB.Query(query, userId)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Failed to retrieve mood logs"})
	}
	defer rows.Close()

	var logs []map[string]interface{}
	for rows.Next() {
		var id int
		var mood, activity, people, timestamp string
		if err := rows.Scan(&id, &userId, &mood, &activity, &people, &timestamp); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Error scanning mood log"})
		}
		log := map[string]interface{}{
			"id":        id,
			"mood":      mood,
			"activity":  activity,
			"people":    people,
			"timestamp": timestamp,
		}
		logs = append(logs, log)
	}

	return c.JSON(fiber.Map{"logs": logs})
}

func SetWakingHours(c *fiber.Ctx) error {
	var data map[string]string
	if err := c.BodyParser(&data); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": "Cannot parse JSON"})
	}

	userId := c.Params("userId") // Retrieve userId from the URL parameter
	wakeUpTime := data["wakeUpTime"]
	sleepTime := data["sleepTime"]

	query := `INSERT INTO UserSettings (userId, wakeUpTime, sleepTime) VALUES (?, ?, ?)
	          ON CONFLICT(userId) DO UPDATE SET wakeUpTime = excluded.wakeUpTime, sleepTime = excluded.sleepTime`

	_, err := config.DB.Exec(query, userId, wakeUpTime, sleepTime)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Failed to set waking hours"})
	}

	return c.JSON(fiber.Map{"message": "Waking hours set successfully"})
}
