package admin

import (
"cyberrange/db"
"cyberrange/types"
"cyberrange/utils"
"fmt"
"net/mail"
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

role := utils.GetRole(token)

if role != "admin" {
return c.JSON(401, map[string]string{"error": "Unauthorized"})
}

email := c.QueryParam("email")

email_without_domain := strings.Split(email, "@")[0]

err := utils.DeleteContainerAndVolume(email_without_domain)
if err != nil {
fmt.Println(err)
}

var user_id, name string
err = db.DB.QueryRow("SELECT user_id,name FROM users WHERE email = ?", email).Scan(&user_id, &name)
if err != nil {
fmt.Println(err)
return c.JSON(500, map[string]string{"error": "Failed to delete the user"})
}

_, err = db.DB.Exec("DELETE FROM users WHERE email = ?", email)
if err != nil {
fmt.Println(err)
return c.JSON(500, map[string]string{"error": "Failed to delete the user"})
}

_, err = db.DB.Exec("DELETE FROM ctf_solves WHERE name = ?", name)
if err != nil {
fmt.Println(err)
return c.JSON(500, map[string]string{"error": "Failed to delete the user"})
}

_, err = db.DB.Exec("DELETE FROM labs_solves WHERE user_id = ?", user_id)
if err != nil {
fmt.Println(err)
return c.JSON(500, map[string]string{"error": "Failed to delete the user"})
}

return c.JSON(200, map[string]string{"message": "User is deleted"})
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