package main

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"io/ioutil"
	"log"
	"time"
)

//Claims can have user id.. etc for Identification purpose
type Claims struct {
	UserId     string `json:"user_id"`
	Authstatus string `json:"authstatus"`
	Role       string `json:"role"`
	Exp        int64  `json:"exp"`
	jwt.StandardClaims
}

var (
	privateKey []byte //openssl genrsa -out privatekey.pem 3072
	publicKey  []byte //openssl rsa -in privatekey.pem -pubout -out publickey.pem
	err        error
)

func init() {
	privateKey, err = ioutil.ReadFile("certs/privatekey.pem")
	errLog(err)
	publicKey, err = ioutil.ReadFile("certs/publickey.pem")
	errLog(err)
}

func AuthHandler(authRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.Request.Header.Get("Authorization") // ie eyJHBxxxxxxxxxxxx

		if len(token) < 1 {
			c.JSON(403, gin.H{"message": "An Authorization token was not supplied"})
			c.Abort()
			return
		}

		if _, err := ValidateToken(token); err != nil {
			fmt.Println(err)
			c.JSON(403, gin.H{"message": "Invalid Authorization token was supplied"})
			c.Abort()
			return
		}

		c.Set("userId", GetClaim(token, "user_id"))
		c.Set("authstatus", GetClaim(token, "authstatus"))
		c.Set("role", GetClaim(token, "role"))

		c.Next()
	}
}

func GenerateToken(userId string, authstatus string, userrole string) (string, error) {

	claims := Claims{
		userId,
		authstatus,
		userrole,
		time.Now().Add(time.Second*900).UnixNano() / int64(time.Second),
		jwt.StandardClaims{},
	}

	privateRSA, _ := jwt.ParseRSAPrivateKeyFromPEM(privateKey)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(privateRSA) // sign the token, return token string, error
}

func ValidateToken(tokenString string) (interface{}, error) {
	if len(tokenString) < 1 {
		return nil, errors.New("an Authorization token was not supplied")
	}
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwt.ParseRSAPublicKeyFromPEM(publicKey) // return *rsa.PublicKey, error
	})
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil // valid token
	} else {
		return nil, err // invalid token
	}
}

func GetClaim(tokenString string, claimreq string) interface{} {
	claims, _ := ValidateToken(tokenString) // validate token
	return claims.(jwt.MapClaims)[claimreq] // return claims
}

func errLog(err error) {
	if err != nil {
		log.Fatal("Error: ", err.Error())
	}
}

func main() {
	token, err := GenerateToken("giftmbanda@gmail.com", "true", "admin") // generate token

	errLog(err)
	fmt.Println(token)

	fmt.Println(GetClaim(token, "user_id"), GetClaim(token, "authstatus"), GetClaim(token, "role"), GetClaim(token, "exp"))
}
