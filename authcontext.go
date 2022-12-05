package hiauth

import (
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"log"
)

type AuthContext struct {
	echo.Context
	ApiKeyID uint32
}

func (ac *AuthContext) DumpKeyID() {
	log.Println(fmt.Sprintf("AuthKeyID: %d\n", ac.ApiKeyID))
}

func extendToAuthedContext(n echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		return n(&AuthContext{Context: c})
	}
}

func keyAuthValidator(k string, c echo.Context) (bool, error) {
	ac := c.(*AuthContext)
	ak := ApiKey{}
	found, err := ak.LoadByKey(k)
	if !found || err != nil || !ak.IsValid() {
		return false, err
	}

	ac.ApiKeyID = ak.ID
	return true, nil
}

func AddGroupKeyAuthMiddleware(g *echo.Group) {
	g.Use(extendToAuthedContext)
	g.Use(middleware.KeyAuthWithConfig(middleware.KeyAuthConfig{
		KeyLookup:  "header:Authorization",
		AuthScheme: "Bearer",
		Validator:  keyAuthValidator,
	}))
}
