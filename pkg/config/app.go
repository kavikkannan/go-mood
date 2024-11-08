package config

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

var DB *sql.DB
	


// Connect opens the SQLite database and creates tables if they don't exist
func Connect() {
	var err error
	DB, err = sql.Open("sqlite3", "./example.db")
	if err != nil {
		panic(err)
	}


	// Create tables if they don't exist
	err = createTables(DB)
	if err != nil {
		log.Fatalf("Failed to create tables: %v", err)
	}
}

// createTables runs SQL statements to create each table if it doesn't exist
func createTables(db *sql.DB) error {
	tableStatements := []string{
		`CREATE TABLE IF NOT EXISTS Login (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			email TEXT NOT NULL UNIQUE,
			password BLOB NOT NULL
		);`,

		`CREATE TABLE IF NOT EXISTS UserSettings (
			userId INTEGER PRIMARY KEY,
			wakeUpTime TIME,
			sleepTime TIME,
			FOREIGN KEY (userId) REFERENCES Login(id) ON DELETE CASCADE
		);`,

		`CREATE TABLE IF NOT EXISTS MoodLogs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			userId INTEGER,
			mood TEXT,
			activity TEXT,
			people TEXT,
			timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (userId) REFERENCES Login(id) ON DELETE CASCADE
		);`,
	}

	for _, stmt := range tableStatements {
		_, err := db.Exec(stmt)
		if err != nil {
			return fmt.Errorf("failed to create table: %w", err)
		}
	}
	return nil
}


// GetDB returns a pointer to the database connection
func GetDB() *sql.DB {
	return DB
}
