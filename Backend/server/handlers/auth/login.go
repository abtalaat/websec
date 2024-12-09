package auth

import (
    "fmt"
    "os"
    "strings"
    "time"

    "cyberrange/db"
    "cyberrange/types"

    "github.com/golang-jwt/jwt"
    "github.com/labstack/echo/v4"

    "golang.org/x/crypto/bcrypt"
    "log"
)

func Login(c echo.Context) error {
    var user types.UserLogin
    if err := c.Bind(&user); err != nil {
        log.Printf("Binding error: %v", err)
        return c.JSON(400, map[string]string{"error": "Invalid input"})
    }
    if user.EmailOrID == "" || user.Password == "" {
        log.Println("Missing required fields")
        return c.JSON(400, map[string]string{"error": "Please provide all required fields"})
    }

    user.EmailOrID = strings.ToLower(user.EmailOrID)

    var role, hashedPassword, name, email, user_id string
    query := "SELECT role, password, name, email, user_id FROM users WHERE (email = ? OR user_id = ?)"
    err := db.DB.QueryRow(query, user.EmailOrID, user.EmailOrID).Scan(&role, &hashedPassword, &name, &email, &user_id)
    if err != nil {
        log.Printf("Database query error for user: %s, error: %v", user.EmailOrID, err)
        return c.JSON(401, map[string]string{"error": "Failed to authenticate"})
    }

    log.Printf("Attempting login for user_id: %s, email: %s", user_id, email)

    // Verify the provided password against the hashed password
    if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(user.Password)); err != nil {
        log.Printf("Password mismatch for user_id: %s", user_id)
        return c.JSON(401, map[string]string{"error": "Invalid credentials"})
    }

    log.Printf("User authenticated successfully: %s", user_id)

    // Generate token
    token, err := generateToken(user_id, role, name, user_id)
    if err != nil {
        log.Printf("Token generation error for user_id: %s, error: %v", user_id, err)
        return c.JSON(500, map[string]string{"error": "Failed to generate token"})
    }

    return c.JSON(200, map[string]string{
        "token": token,
        "role":  role,
        "name":  name,
    })
}

func generateToken(id, role, name, user_id string) (string, error) {
    secretKey := os.Getenv("JWT_SECRET")
    if secretKey == "" {
        return "", fmt.Errorf("JWT_SECRET is not set")
    }

    return createToken(id, role, name, user_id, []byte(secretKey))
}

func createToken(id, role, name, user_id string, secretKey []byte) (string, error) {
    claims := jwt.MapClaims{
        "id":      id,
        "role":    role,
        "name":    name,
        "user_id": user_id,
        "iat":     time.Now().Unix(),
        "exp":     time.Now().Add(time.Hour * 24 * 30).Unix(),
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    signedToken, err := token.SignedString(secretKey)
    if err != nil {
        return "", err
    }

    return signedToken, nil
}
