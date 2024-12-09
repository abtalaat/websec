package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"html"
	"strings"
	"time"

	"cyberrange/db"
	"cyberrange/types"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
)

func sanitizeInput(input string) string {
	return html.EscapeString(strings.TrimSpace(input))
}

// Function to generate a random OTP (6-8 alphanumeric characters)
func generateOTP() (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	var otp []byte
	otpLength := 8 // We use 8 characters for more security

	for i := 0; i < otpLength; i++ {
		randomIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		otp = append(otp, charset[randomIndex.Int64()])
	}
	return string(otp), nil
}

// Function to simulate sending OTP email
func sendOTPEmail(email, otp string) error {
	// Your email sending logic here...
	// For example, using a service like SendGrid, AWS SES, etc.
	fmt.Printf("Sending OTP %s to email: %s\n", otp, email) // Simulate email send
	return nil
}

func Register(c echo.Context) error {
	user := types.UserRegister{}

	// Bind input
	if err := c.Bind(&user); err != nil {
		return c.JSON(400, map[string]string{"error": err.Error()})
	}

	// Sanitize and validate fields
	user.ID = sanitizeInput(user.ID)
	user.Email = strings.ToLower(sanitizeInput(user.Email))
	user.Password = sanitizeInput(user.Password)
	user.Name = sanitizeInput(user.Name)

	if user.ID == "" || user.Email == "" || user.Password == "" || user.Name == "" {
		return c.JSON(400, map[string]string{"error": "Please provide all the required fields"})
	}

	// Check if the ID or Email already exists in the database
	var existingEmail string
	err := db.DB.QueryRow("SELECT email FROM users WHERE email = ?", user.Email).Scan(&existingEmail)
	if err == nil {
		return c.JSON(400, map[string]string{"error": "Email is already registered"})
	}

	// Generate OTP for email verification
	otp, err := generateOTP()
	if err != nil {
		return c.JSON(500, map[string]string{"error": "Failed to generate OTP"})
	}

	// Store OTP in the database (hash it for security)
	hashedOTP, err := bcrypt.GenerateFromPassword([]byte(otp), bcrypt.DefaultCost)
	if err != nil {
		return c.JSON(500, map[string]string{"error": "Failed to hash OTP"})
	}

	// Insert the OTP and expiration date into the database (for simplicity, just store OTP hash and expiry)
	expiry := time.Now().Add(10 * time.Minute) // OTP expiry time (10 minutes)

	_, err = db.DB.Exec(
		"INSERT INTO email_verifications (email, otp, expiry) VALUES (?, ?, ?)",
		user.Email, hashedOTP, expiry,
	)
	if err != nil {
		return c.JSON(500, map[string]string{"error": "Failed to store OTP"})
	}

	// Send OTP via email
	err = sendOTPEmail(user.Email, otp)
	if err != nil {
		return c.JSON(500, map[string]string{"error": "Failed to send OTP email"})
	}

	// Return a message asking the user to check their email
	return c.JSON(200, map[string]string{"message": "Verification email sent. Please check your inbox."})
}


func VerifyOTP(c echo.Context) error {
	verify := types.VerifyOTPRequest{}

	// Bind input
	if err := c.Bind(&verify); err != nil {
		return c.JSON(400, map[string]string{"error": err.Error()})
	}

	// Sanitize input
	verify.Email = strings.ToLower(sanitizeInput(verify.Email))
	verify.OTP = sanitizeInput(verify.OTP)
	verify.Password = sanitizeInput(verify.Password)
	verify.ConfirmPassword = sanitizeInput(verify.ConfirmPassword)

	// Validate fields
	if verify.Email == "" || verify.OTP == "" || verify.Password == "" || verify.ConfirmPassword == "" {
		return c.JSON(400, map[string]string{"error": "All fields are required"})
	}

	if verify.Password != verify.ConfirmPassword {
		return c.JSON(400, map[string]string{"error": "Passwords do not match"})
	}

	if len(verify.Password) < 8 {
		return c.JSON(400, map[string]string{"error": "Password must be at least 8 characters long"})
	}

	// Retrieve OTP from the database
	var storedHashedOTP string
	var expiry time.Time
	err := db.DB.QueryRow("SELECT otp, expiry FROM email_verifications WHERE email = ?", verify.Email).Scan(&storedHashedOTP, &expiry)
	if err != nil {
		return c.JSON(400, map[string]string{"error": "No OTP request found for this email"})
	}

	// Check if OTP is expired
	if time.Now().After(expiry) {
		return c.JSON(400, map[string]string{"error": "OTP has expired"})
	}

	// Compare OTPs
	err = bcrypt.CompareHashAndPassword([]byte(storedHashedOTP), []byte(verify.OTP))
	if err != nil {
		return c.JSON(400, map[string]string{"error": "Invalid OTP"})
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(verify.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.JSON(500, map[string]string{"error": "Failed to hash password"})
	}

	// Insert the new user into the database
	_, err = db.DB.Exec(
		"INSERT INTO users (id, email, password, name) VALUES (?, ?, ?, ?)",
		verify.ID, verify.Email, hashedPassword, verify.Name,
	)
	if err != nil {
		return c.JSON(500, map[string]string{"error": "Failed to create user"})
	}

	// Delete the OTP record as it's no longer needed
	_, err = db.DB.Exec("DELETE FROM email_verifications WHERE email = ?", verify.Email)
	if err != nil {
		return c.JSON(500, map[string]string{"error": "Failed to clean up OTP"})
	}

	// Return success message
	return c.JSON(200, map[string]string{"message": "Account created successfully"})
}
b. Define Request Types
Ensure you have the necessary request types defined in your types package.

go
Copy code
// types/user.go
package types

type UserRegister struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

type VerifyOTPRequest struct {
	ID              string `json:"id"`
	Email           string `json:"email"`
	OTP             string `json:"otp"`
	Password        string `json:"password"`
	ConfirmPassword string `json:"confirm_password"`
}