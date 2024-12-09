package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"cyberrange/db"
	"github.com/labstack/echo/v4"
)

type ForgetPassword struct {
	Email string `json:"email"`
}

var otpCache = make(map[string]OTPInfo)

type OTPInfo struct {
	OTP        string
	CreatedAt  time.Time
	ExpiryTime time.Time
}

var rateLimitCache = make(map[string]int)

const (
	otpExpiryDuration = 5 * time.Minute  
	rateLimitDuration = 10 * time.Minute 
	maxRequests       = 5                
)

func generateOTP() (string, error) {
	otpLength := 8
	otp := make([]byte, otpLength)
	_, err := rand.Read(otp)
	if err != nil {
		return "", err
	}

	otpString := base64.URLEncoding.EncodeToString(otp)

	return otpString, nil
}

func sendOTPEmail(email, otp string) error {
	fmt.Printf("Sending OTP: %s to email: %s\n", otp, email)
	return nil
}

func ForgetP(c echo.Context) error {
	var forgetPassword ForgetPassword
	err := c.Bind(&forgetPassword)
	if err != nil {
		return c.JSON(400, map[string]string{"error": err.Error()})
	}

	if forgetPassword.Email == "" {
		return c.JSON(400, map[string]string{"error": "Please provide the email"})
	}

	forgetPassword.Email = strings.ToLower(forgetPassword.Email)

	if rateLimitCache[forgetPassword.Email] >= maxRequests {
		return c.JSON(429, map[string]string{"error": "Too many OTP requests. Please try again later."})
	}

	rateLimitCache[forgetPassword.Email]++
	go func() {
		time.Sleep(rateLimitDuration)
		rateLimitCache[forgetPassword.Email]--
	}()

	var email string
	err = db.DB.QueryRow("SELECT email FROM users WHERE email = ?", forgetPassword.Email).Scan(&email)
	if err != nil {
		return c.JSON(200, map[string]string{"message": "If this email exists, an OTP will be sent shortly."})
	}

	otp, err := generateOTP()
	if err != nil {
		return c.JSON(500, map[string]string{"error": "Failed to generate OTP"})
	}

	otpCache[forgetPassword.Email] = OTPInfo{
		OTP:        otp,
		CreatedAt:  time.Now(),
		ExpiryTime: time.Now().Add(otpExpiryDuration),
	}

	err = sendOTPEmail(forgetPassword.Email, otp)
	if err != nil {
		return c.JSON(500, map[string]string{"error": "Failed to send OTP email"})
	}

	return c.JSON(200, map[string]string{"message": "OTP sent successfully"})
}
