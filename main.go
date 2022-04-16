package main

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"io/ioutil"
	"log"
	"strings"
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
	privateKey []byte //openssl genrsa -out jwt-private.pem 3072
	publicKey  []byte //openssl rsa -in jwt-private.pem -pubout -out jwt-public.pem
	err        error
)

func init() {
	privateKey, err = ioutil.ReadFile("certs/chain.key")
	errLog(err)
	publicKey, err = ioutil.ReadFile("certs/chain.pem")
	errLog(err)
}

func AuthHandler(authRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.Request.Header.Get("Authorization")
		// Check if token in correct format
		// ie eyJHBxxxxxxxxx
		b := "eyJhb"
		if !strings.Contains(token, b) {
			c.JSON(403, gin.H{"message": "Your request is not authorized"})
			c.Abort()
			return
		}

		t := strings.Split(token, b)
		if len(t) < 2 {
			c.JSON(403, gin.H{"message": "An authorization token was not supplied"})
			c.Abort()
			return
		}

		claims, err := ValidateToken(token)
		if err != nil {
			fmt.Println(err)
			c.JSON(403, gin.H{"message": "Invalid authorization token"})
			c.Abort()
			return
		}

		claimValue := claims.(jwt.MapClaims) //

		//fmt.Println(claimValue["user_id"], claimValue["authstatus"])
		c.Set("userId", claimValue["user_id"])
		c.Set("authstatus", claimValue["authstatus"])
		c.Set("role", claimValue["role"])
		c.Next()
	}
}

func GenerateToken(userId string, authstatus string, userrole string) (string, error) {
	privateRSA, err := jwt.ParseRSAPrivateKeyFromPEM(privateKey)
	errLog(err)

	claims := Claims{
		userId,
		authstatus,
		userrole,
		time.Now().Add(time.Second*900).UnixNano() / int64(time.Second),
		jwt.StandardClaims{},
	}

	signedString := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token, err := signedString.SignedString(privateRSA)
	return token, err
}

func ValidateToken(inToken string) (interface{}, error) {
	publicRSA := ParseRSAPublicKey()

	token, err := jwt.Parse(inToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicRSA, err
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil // fmt.Println("Valid token")

	} else {
		return nil, err // fmt.Println("Invalid token")
	}
}

func GetClaim(jwtToken string, claimreq string) interface{} {
	claims, err := ValidateToken(jwtToken) // validate token
	errLog(err)
	claimValue := claims.(jwt.MapClaims)
	return claimValue[claimreq] // return claims
}

func errLog(err error) {
	if err != nil {
		log.Fatal("Error: ", err.Error())
	}
}

func ParseRSAPublicKey() interface{} {
	publicRSA, err := jwt.ParseRSAPublicKeyFromPEM(publicKey)
	errLog(err)
	return publicRSA
}

func main() {
	token, err := GenerateToken("giftmbanda@gmail.com", "true", "admin") //generate token

	errLog(err)
	fmt.Println(token)

	fmt.Println(GetClaim(token, "user_id"), GetClaim(token, "authstatus"), GetClaim(token, "role"), GetClaim(token, "exp"))
}
