package main

import (
	_ "embed"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	_ "embed"

	"github.com/pilcrowonpaper/go-json"
	"github.com/pilcrowonpaper/passwordless-example.auth.pilcrowonpaper.com/ratelimit"

	"golang.org/x/sync/semaphore"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

const databaseFilename = "data.db"

//go:embed schema.sql
var schemaSQLScript string

type serverStruct struct {
	emailClient emailClientInterface

	databaseReadConnectionPool  *sqlitex.Pool
	databaseWriteConnectionPool *sqlitex.Pool
	cpuIntensiveSemaphore       *semaphore.Weighted
	origin                      string
	webauthnRelyingPartyId      string
	webauthnAuthenticatorNames  map[string]string

	logging serverLoggingStruct

	userEmailCodeVerificationAuthenticationRateLimit *ratelimit.LimitStruct
	emailAddressVerificationRateLimit                *ratelimit.LimitStruct
	emailRateLimit                                   *ratelimit.LimitStruct
	requestRateLimit                                 *ratelimit.LimitStruct
}

func (server *serverStruct) https() bool {
	return strings.HasPrefix(server.origin, "https://")
}

func (server *serverStruct) getWebauthnAuthenticatorName(authenticatorId []byte) (string, bool) {
	name, ok := server.webauthnAuthenticatorNames[string(authenticatorId)]
	return name, ok
}

type serverLoggingStruct struct {
	internalError bool
	backgroundJob bool
	actionResult  bool
	requestEmail  bool
	requestEvent  bool
}

//go:embed server_assets/webauthn_authenticators.json
var webauthnAuthenticatorsJSON string

func createServer(emailClient emailClientInterface, origin string, webauthnRelyingPartyId string, logging serverLoggingStruct) (*serverStruct, error) {
	databaseReadConnectionPool, err := sqlitex.NewPool(databaseFilename, sqlitex.PoolOptions{
		Flags:    sqlite.OpenReadWrite | sqlite.OpenWAL,
		PoolSize: runtime.NumCPU(),
		PrepareConn: func(conn *sqlite.Conn) error {
			err := sqlitex.ExecuteTransient(conn, "PRAGMA foreign_keys = ON", nil)
			if err != nil {
				return fmt.Errorf("failed to enable foreign keys: %s", err.Error())
			}
			return nil
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create sqlite read connection pool: %s", err.Error())
	}

	databaseWriteConnectionPool, err := sqlitex.NewPool(databaseFilename, sqlitex.PoolOptions{
		Flags:    sqlite.OpenReadWrite | sqlite.OpenWAL,
		PoolSize: 1,
		PrepareConn: func(conn *sqlite.Conn) error {
			err := sqlitex.ExecuteTransient(conn, "PRAGMA foreign_keys = ON", nil)
			if err != nil {
				return fmt.Errorf("failed to enable foreign keys: %s", err.Error())
			}
			return nil
		},
	})
	if err != nil {
		databaseReadConnectionPool.Close()
		return nil, fmt.Errorf("failed to create sqlite write connection pool: %s", err.Error())
	}

	cpuIntensiveSemaphore := semaphore.NewWeighted(int64(runtime.NumCPU()))

	userEmailCodeVerificationAuthenticationRateLimit := ratelimit.NewLimit(1_000, 5, time.Minute)
	emailAddressVerificationRateLimit := ratelimit.NewLimit(1_000, 5, time.Minute)
	emailRateLimit := ratelimit.NewLimit(1_000, 5, 30*time.Minute)
	requestRateLimit := ratelimit.NewLimit(10_000, 100, time.Second)

	webauthnAuthenticatorNames := map[string]string{}

	webauthnAuthenticatorsJSONObject, err := json.ParseObject(webauthnAuthenticatorsJSON)
	if err != nil {
		databaseReadConnectionPool.Close()
		databaseWriteConnectionPool.Close()

		return nil, fmt.Errorf("failed to parse webauthn authenticators object json: %s", err.Error())
	}
	for _, encodedAuthenticatorId := range webauthnAuthenticatorsJSONObject.Keys {
		authenticatorId, err := base64.StdEncoding.DecodeString(encodedAuthenticatorId)
		if err != nil {
			databaseReadConnectionPool.Close()
			databaseWriteConnectionPool.Close()

			return nil, fmt.Errorf("failed to base64 decode authenticator id: %s", err.Error())
		}

		authenticatorName, err := webauthnAuthenticatorsJSONObject.GetString(encodedAuthenticatorId)
		if err != nil {
			databaseReadConnectionPool.Close()
			databaseWriteConnectionPool.Close()

			return nil, fmt.Errorf("failed to get authenticator name: %s", err.Error())
		}

		webauthnAuthenticatorNames[string(authenticatorId)] = authenticatorName
	}

	server := &serverStruct{
		emailClient:                 emailClient,
		databaseReadConnectionPool:  databaseReadConnectionPool,
		databaseWriteConnectionPool: databaseWriteConnectionPool,
		cpuIntensiveSemaphore:       cpuIntensiveSemaphore,
		origin:                      origin,
		webauthnRelyingPartyId:      webauthnRelyingPartyId,
		webauthnAuthenticatorNames:  webauthnAuthenticatorNames,
		logging:                     logging,
		userEmailCodeVerificationAuthenticationRateLimit: userEmailCodeVerificationAuthenticationRateLimit,
		emailAddressVerificationRateLimit:                emailAddressVerificationRateLimit,
		emailRateLimit:                                   emailRateLimit,
		requestRateLimit:                                 requestRateLimit,
	}

	return server, nil
}

func (server *serverStruct) start(port int) error {
	go server.clearDataBackgroundJob()

	httpSever := &http.Server{
		Addr:           fmt.Sprintf(":%d", port),
		Handler:        http.MaxBytesHandler(http.HandlerFunc(server.handleRequest), 1024*16),
		MaxHeaderBytes: 1024 * 16,
		ReadTimeout:    30 * time.Second,
	}

	err := httpSever.ListenAndServe()
	if err != nil {
		return fmt.Errorf("failed to listen and serve: %s", err.Error())
	}

	return nil
}

func (server *serverStruct) handleRequest(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if err := recover(); err != nil {
			// Just kill the server if it panics

			stack := debug.Stack()
			fmt.Fprintf(os.Stderr, "%v\n", err)
			fmt.Fprintf(os.Stderr, "%s\n", stack)
			os.Exit(1)
		}
	}()

	requestId := r.Header.Get("X-Railway-Request-Id")
	if requestId == "" {
		requestId = generateLongItemId()
	}

	clientIPAddress := r.Header.Get("X-Real-IP")
	if clientIPAddress != "" {
		rateLimitAllowed := server.requestRateLimit.Consume(clientIPAddress)
		if !rateLimitAllowed {
			w.WriteHeader(429)
			return
		}
	}

	pathParts := strings.Split(r.URL.Path, "/")[1:]

	// Remove single trailing slash
	if len(pathParts) > 0 && pathParts[len(pathParts)-1] == "" {
		pathParts = pathParts[:len(pathParts)-1]
	}

	// GET /
	if len(pathParts) == 0 && r.Method == "GET" {
		server.homePageRoute(w, r, requestId, clientIPAddress)
		return
	}

	// /sign-up
	if len(pathParts) > 0 && pathParts[0] == "sign-up" {
		// GET /sign-up
		if len(pathParts) == 1 && r.Method == "GET" {
			server.signUpPageRoute(w, r, requestId, clientIPAddress)
			return
		}

		// GET /sign-up/verify-email-address
		if len(pathParts) == 2 && pathParts[1] == "verify-email-address" && r.Method == "GET" {
			server.signUpVerifyEmailAddressPageRoute(w, r, requestId, clientIPAddress)
			return
		}

		// /sign-up/register-passkey
		if len(pathParts) > 1 && pathParts[1] == "register-passkey" {
			// GET /sign-up/register-passkey
			if len(pathParts) == 2 && r.Method == "GET" {
				server.signUpRegisterPasskeyPageRoute(w, r, requestId, clientIPAddress)
				return
			}

			// GET /sign-up/register-passkey/set-passkey-name
			if len(pathParts) == 3 && pathParts[2] == "set-passkey-name" && r.Method == "GET" {
				server.signUpRegisterPasskeySetPasskeyNamePageRoute(w, r, requestId, clientIPAddress)
				return
			}
		}
	}

	// /sign-in
	if len(pathParts) > 0 && pathParts[0] == "sign-in" {
		// GET /sign-in
		if len(pathParts) == 1 && r.Method == "GET" {
			server.signInPageRoute(w, r, requestId, clientIPAddress)
			return
		}

		// /sign-in/verify-email-code
		if len(pathParts) == 2 && pathParts[1] == "verify-email-code" && r.Method == "GET" {
			server.signInVerifyEmailCodePageRoute(w, r, requestId, clientIPAddress)
			return
		}
	}

	// /verify-identity
	if len(pathParts) > 0 && pathParts[0] == "verify-identity" {
		// GET /verify-identity
		if len(pathParts) == 1 && r.Method == "GET" {
			server.verifyIdentityPageRoute(w, r, requestId, clientIPAddress)
			return
		}

		// /verify-identity/verify-email-code
		if len(pathParts) == 2 && pathParts[1] == "verify-email-code" && r.Method == "GET" {
			server.verifyIdentityVerifyEmailCodePageRoute(w, r, requestId, clientIPAddress)
			return
		}
	}

	// GET /account
	if len(pathParts) == 1 && pathParts[0] == "account" && r.Method == "GET" {
		server.accountPageRoute(w, r, requestId, clientIPAddress)
		return
	}

	// /update-email-address
	if len(pathParts) > 0 && pathParts[0] == "update-email-address" {
		// GET /update-email-address/set-new-email-address
		if len(pathParts) == 2 && pathParts[1] == "set-new-email-address" && r.Method == "GET" {
			server.updateEmailAddressSetNewEmailAddressPageRoute(w, r, requestId, clientIPAddress)
			return
		}

		// GET /update-email-address/verify-new-email-address
		if len(pathParts) == 2 && pathParts[1] == "verify-new-email-address" && r.Method == "GET" {
			server.updateEmailAddressVerifyNewEmailAddressPageRoute(w, r, requestId, clientIPAddress)
			return
		}
	}

	// /delete-account
	if len(pathParts) > 0 && pathParts[0] == "delete-account" {
		// GET /delete-account/confirm
		if len(pathParts) == 2 && pathParts[1] == "confirm" && r.Method == "GET" {
			server.deleteAccountConfirmPageRoute(w, r, requestId, clientIPAddress)
			return
		}
	}

	// /register-passkey
	if len(pathParts) > 0 && pathParts[0] == "register-passkey" {
		// GET /register-passkey/set-authenticator-webauthn-credential
		if len(pathParts) == 2 && pathParts[1] == "create-passkey" && r.Method == "GET" {
			server.registerPasskeyCreatePasskeyPageRoute(w, r, requestId, clientIPAddress)
			return
		}

		// GET /register-passkey/set-authenticator-name
		if len(pathParts) == 2 && pathParts[1] == "set-passkey-name" && r.Method == "GET" {
			server.registerPasskeySetPasskeyNamePageRoute(w, r, requestId, clientIPAddress)
			return
		}
	}

	// /delete-passkey
	if len(pathParts) > 0 && pathParts[0] == "delete-passkey" {
		// GET /delete-passkey/confirm
		if len(pathParts) == 2 && pathParts[1] == "confirm" && r.Method == "GET" {
			server.deletePasskeyConfirmPageRoute(w, r, requestId, clientIPAddress)
			return
		}
	}

	// POST /action
	if len(pathParts) == 1 && pathParts[0] == "action" && r.Method == "POST" {
		server.actionRoute(w, r, requestId, clientIPAddress)
		return
	}

	w.WriteHeader(404)
	w.Write([]byte("The page you're looking for doesn't exist."))
}
