package auth

import (
	"crypto/rand"
	"fmt"
	"html"
	"math/big"
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
func generateRegisterOTP() (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	var otp []byte
	otpLength := 8 // 8 characters for more security

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
func sendRegisterOTPEmail(email, otp string) error {
	// Your email sending logic here...
	// For example, using SendGrid, AWS SES, etc.
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

	// Check if the Email already exists
	var existingEmail string
	err := db.DB.QueryRow("SELECT email FROM users WHERE email = ?", user.Email).Scan(&existingEmail)
	if err == nil {
		return c.JSON(400, map[string]string{"error": "Email is already registered"})
	}

	// Generate OTP for email verification
	otp, err := generateRegisterOTP()
	if err != nil {
		return c.JSON(500, map[string]string{"error": "Failed to generate OTP"})
	}

	// Store OTP in the database (hash it for security)
	hashedOTP, err := bcrypt.GenerateFromPassword([]byte(otp), bcrypt.DefaultCost)
	if err != nil {
		return c.JSON(500, map[string]string{"error": "Failed to hash OTP"})
	}

	expiry := time.Now().Add(10 * time.Minute) // OTP expires in 10 minutes

	_, err = db.DB.Exec(
		"INSERT INTO email_verifications (email, otp, expiry) VALUES (?, ?, ?)",
		user.Email, hashedOTP, expiry,
	)
	if err != nil {
		return c.JSON(500, map[string]string{"error": "Failed to store OTP"})
	}

	// Send OTP via email
	err = sendRegisterOTPEmail(user.Email, otp)
	if err != nil {
		return c.JSON(500, map[string]string{"error": "Failed to send OTP email"})
	}

	// Ask the user to check their email for the OTP
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
	verify.ID = sanitizeInput(verify.ID)
	verify.Name = sanitizeInput(verify.Name)

	// Validate fields
	if verify.Email == "" || verify.OTP == "" || verify.Password == "" || verify.ConfirmPassword == "" || verify.ID == "" || verify.Name == "" {
		return c.JSON(400, map[string]string{"error": "All fields are required"})
	}

	if verify.Password != verify.ConfirmPassword {
		return c.JSON(400, map[string]string{"error": "Passwords do not match"})
	}

	if len(verify.Password) < 8 {
		return c.JSON(400, map[string]string{"error": "Password must be at least 8 characters long"})
	}

	var storedHashedOTP string
	var expiry time.Time
	err := db.DB.QueryRow("SELECT otp, expiry FROM email_verifications WHERE email = ?", verify.Email).Scan(&storedHashedOTP, &expiry)
	if err != nil {
		return c.JSON(400, map[string]string{"error": "No OTP request found for this email"})
	}

	if time.Now().After(expiry) {
		return c.JSON(400, map[string]string{"error": "OTP has expired"})
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedHashedOTP), []byte(verify.OTP))
	if err != nil {
		return c.JSON(400, map[string]string{"error": "Invalid OTP"})
	}

	// Hash the password for the user
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(verify.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.JSON(500, map[string]string{"error": "Failed to hash password"})
	}

	_, err = db.DB.Exec(
		"INSERT INTO users (user_id, email, password, name) VALUES (?, ?, ?, ?)",
		verify.ID, verify.Email, hashedPassword, verify.Name,
	)
	if err != nil {
		return c.JSON(500, map[string]string{"error": "Failed to create user"})
	}

	// Delete the OTP record
	_, err = db.DB.Exec("DELETE FROM email_verifications WHERE email = ?", verify.Email)
	if err != nil {
		return c.JSON(500, map[string]string{"error": "Failed to clean up OTP"})
	}

	return c.JSON(200, map[string]string{"message": "Account created successfully"})
}
