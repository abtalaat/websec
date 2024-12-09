package admin

import (
"cyberrange/db"
"cyberrange/types"
"cyberrange/utils"
"fmt"
"net/mail"
"regexp"
"strings"

"github.com/labstack/echo/v4"
)

func GetUsers(c echo.Context) error {
token := c.Request().Header.Get("Authorization")

role := utils.GetRole(token)

if role != "admin" {
return c.JSON(401, map[string]string{"error": "Unauthorized"})
}

users := []types.User{}

rows, err := db.DB.Query("SELECT email, user_id, name,attack_defense_role FROM users WHERE role = 'user'")
if err != nil {
fmt.Println(err)
return c.JSON(500, map[string]string{"error": "Failed to get users"})
}

defer rows.Close()

for rows.Next() {
user := types.User{}
err := rows.Scan(&user.Email, &user.User_id, &user.Name, &user.Attack_defense_role)
if err != nil {
fmt.Println(err)
return c.JSON(500, map[string]string{"error": "Failed to get users"})
}
users = append(users, user)
}

return c.JSON(200, users)
}

// Helper function to validate email format
func isValidEmail(email string) bool {
_, err := mail.ParseAddress(email)
return err == nil
}

// Restrict domain function
func isAllowedDomain(email string, allowedDomains []string) bool {
for _, domain := range allowedDomains {
if strings.HasSuffix(email, "@"+domain) {
return true
}
}
return false
}

func MakeAdmin(c echo.Context) error {
token := c.Request().Header.Get("Authorization")

// Validate the user role
role := utils.GetRole(token)
if role != "admin" {
return c.JSON(401, map[string]string{"error": "Unauthorized"})
}

email := c.QueryParam("email")

// Validate email format
if !isValidEmail(email) {
return c.JSON(400, map[string]string{"error": "Invalid email format"})
}

// Restrict email to specific domains
allowedDomains := []string{"aucegypt.edu"}
if !isAllowedDomain(email, allowedDomains) {
return c.JSON(400, map[string]string{"error": "Email domain not allowed"})
}

// Check if email exists in the database
var userExists bool
err := db.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE email = ?)", email).Scan(&userExists)
if err != nil || !userExists {
return c.JSON(404, map[string]string{"error": "Email does not exist"})
}

// Update the user role to admin
_, err = db.DB.Exec("UPDATE users SET role = 'admin' WHERE email = ?", email)
if err != nil {
fmt.Println(err)
return c.JSON(500, map[string]string{"error": "Failed to make the user admin"})
}
println("user passed")
return c.JSON(200, map[string]string{"message": "User is now an admin"})
}

func DeleteUser(c echo.Context) error {
token := c.Request().Header.Get("Authorization")

// Check user role
role := utils.GetRole(token)
if role != "admin" {
return c.JSON(401, map[string]string{"error": "Unauthorized"})
}

// Get and validate the email parameter
email := c.QueryParam("email")
email = strings.TrimSpace(email)
if email == "" {
return c.JSON(400, map[string]string{"error": "Email parameter is required"})
}

// Validate email format
re := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
if !re.MatchString(email) {
return c.JSON(400, map[string]string{"error": "Invalid email format"})
}

// Extract the email prefix (before @)
emailWithoutDomain := strings.Split(email, "@")[0]

// Delete associated container and volume
err := utils.DeleteContainerAndVolume(emailWithoutDomain)
if err != nil {
fmt.Printf("Failed to delete container and volume: %s\n", err)
}

// Use parameterized queries to safely delete user and associated data
var userID, name string

// Retrieve user ID and name
err = db.DB.QueryRow("SELECT user_id, name FROM users WHERE email = ?", email).Scan(&userID, &name)
if err != nil {
fmt.Printf("Failed to retrieve user: %s\n", err)
return c.JSON(500, map[string]string{"error": "Failed to retrieve user data"})
}

// Delete user record
_, err = db.DB.Exec("DELETE FROM users WHERE email = ?", email)
if err != nil {
fmt.Printf("Failed to delete user: %s\n", err)
return c.JSON(500, map[string]string{"error": "Failed to delete the user"})
}

// Delete associated CTF solves
_, err = db.DB.Exec("DELETE FROM ctf_solves WHERE name = ?", name)
if err != nil {
fmt.Printf("Failed to delete CTF solves: %s\n", err)
return c.JSON(500, map[string]string{"error": "Failed to delete CTF solves"})
}

// Delete associated lab solves
_, err = db.DB.Exec("DELETE FROM labs_solves WHERE user_id = ?", userID)
if err != nil {
fmt.Printf("Failed to delete lab solves: %s\n", err)
return c.JSON(500, map[string]string{"error": "Failed to delete lab solves"})
}

return c.JSON(200, map[string]string{"message": "User has been deleted successfully"})
}

func GetFeedbacks(c echo.Context) error {
token := c.Request().Header.Get("Authorization")

role := utils.GetRole(token)

if role != "admin" {
return c.JSON(401, map[string]string{"error": "Unauthorized"})
}

feedbacks := []types.Feedback{}

rows, err := db.DB.Query("SELECT id, name, feedback,type ,created_at FROM feedback")
if err != nil {
fmt.Println(err)
return c.JSON(500, map[string]string{"error": "Failed to get feedbacks"})
}
defer rows.Close()

for rows.Next() {
feedback := types.Feedback{}
err := rows.Scan(&feedback.ID, &feedback.Name, &feedback.Feedback, &feedback.Type, &feedback.Created_at)
if err != nil {
fmt.Println(err)
return c.JSON(500, map[string]string{"error": "Failed to get feedbacks"})
}
feedbacks = append(feedbacks, feedback)
}

return c.JSON(200, map[string]interface{}{"feedbacks": feedbacks})
}