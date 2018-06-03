package main

//go:generate sh -c "(echo 'package main';echo;echo 'const index = `'; cat index.html; echo '`' )>index_gen.go"

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/docopt/docopt-go"
	"github.com/google/uuid"
	"github.com/mitchellh/go-homedir"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	goauth2 "google.golang.org/api/oauth2/v2"
)

const help = `Usage:
	google-jwt [options] [--email=<email>...]

Options:
	--no-secure                   Stores the authentication without the secure option (cookie exposed on http as well as https)
	--display                     Displays the authentiation token in the home page. This allows the user to easily copy-paste the token in his .netrc
	--expose-public-key           Adds an endpoint to download the public key
	--client-secret-file=<name>   The path to which the google client secret has been downloaded [Default: client_secret.json]
	--cookie-name=<name>          The name of the cookie the token will be stored in [Default: token]
	--key=<key>                   The raw encoding key to be used
	--key-path=<path>             The path to the private key to encode the token.
	--key-env=<name>              The name of the environment variable containing to the private key to encode the token.
	--email=<email>               Adds an email to be whitelisted. Email will be matched using the glob pattern. any * caracter will match any string
	--listen=<address>, -l        The interface to listen on [Default: 0.0.0.0:8080]
`

var (
	secure              = true
	display             = false
	cookieName          = "token"
	cookieEncodingKey   interface{}
	cookieDecodingKey   interface{}
	cookieSigningMethod jwt.SigningMethod
)

type idx struct {
	Token string
	Netrc string
}

func count(values ...interface{}) int {
	count := 0
	for _, v := range values[:] {
		if v != nil {
			count++
		}
	}
	return count
}

// Handles a user friendly path and reads its content
func readUserFriendlyFilePath(path string) ([]byte, error) {
	path, err := homedir.Expand(path)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve key path: %v", err)
	}
	return ioutil.ReadFile(path)
}

// From crypto/tls
// Attempt to parse the given private key DER block. OpenSSL 0.9.8 generates
// PKCS#1 private keys by default, while OpenSSL 1.0.0 generates PKCS#8 keys.
// OpenSSL ecparam generates SEC1 EC private keys for ECDSA. We try all three.
func parsePemPrivateKey(block *pem.Block) (interface{}, error) {
	if !strings.HasSuffix(block.Type, "PRIVATE KEY") {
		return nil, fmt.Errorf("unknown pem type %s, expecting PRIVATE KEY suffix", block.Type)
	}
	der := block.Bytes
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("tls: found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("tls: failed to parse private key")
}

func getPrivateKey(bytes []byte) (interface{}, error) {
	block, _ := pem.Decode(bytes)
	if block == nil {
		log.Printf("Failed to parse PEM, using raw data as key\n")
		return bytes, nil
	}
	return parsePemPrivateKey(block)
}

func netrc(machine, token string) string {
	return "machine " + machine + "\n  password " + token + "\n"
}

func setCookie(w http.ResponseWriter, email string, key interface{}) error {

	expires := time.Now().Add(30 * 24 * time.Hour)
	claims := jwt.StandardClaims{
		Id:        email,
		NotBefore: time.Now().Unix(),
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: expires.Unix(),
	}
	t, err := jwt.NewWithClaims(cookieSigningMethod, claims).SignedString(key)
	if err != nil {
		return fmt.Errorf("failed to generate token: %s", err.Error())
	}

	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    t,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   secure,
	})
	return nil
}

func exchangeTokenForEmail(config *oauth2.Config, code string) (string, error) {

	token, err := config.Exchange(context.Background(), code)
	if err != nil {
		return "", fmt.Errorf("Token exchange error: %v", err)
	}
	client := config.Client(context.Background(), token)
	oauth2Service, err := goauth2.New(client)
	if err != nil {
		return "", fmt.Errorf("Oauth2 client error: %v", err)
	}
	i, err := oauth2Service.Userinfo.Get().Do()
	if err != nil {
		return "", fmt.Errorf("User info error: %v", err)
	}
	return i.Email, nil
}

func getConfigForRequest(config *oauth2.Config, r *http.Request) *oauth2.Config {
	protocol := "https"
	if !secure {
		// TODO handle X-Forwarded-Proto based on trusted forwarders
		protocol = "http"
	}
	path := strings.TrimSuffix(r.URL.Path, "/auth")
	path = strings.TrimSuffix(path, "/token")
	path = strings.TrimSuffix(path, "/")
	u := &url.URL{
		Scheme: protocol,
		Host:   r.Host,
		Path:   path + "/token",
		Opaque: r.URL.Opaque,
	}
	c := *config
	c.RedirectURL = u.String()
	return &c
}

func redirectHandler(config *oauth2.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state := uuid.New().String()
		w.Header().Set("Location", getConfigForRequest(config, r).AuthCodeURL(state))
		w.WriteHeader(http.StatusFound)
		log.Printf("New login request: state: %s", state)
	}
}

func emailMatched(email string, acceptedMails []string) bool {
	if len(acceptedMails) == 0 {
		return true
	}
	for _, e := range acceptedMails[:] {
		matched, err := filepath.Match(e, email)
		if err != nil {
			log.Printf("Error matching %s with %s: %v", email, e, err)
		} else if matched {
			return true
		}
	}
	return false
}

func main() {
	args, err := docopt.Parse(help, os.Args[1:], true, "0.0", false)
	fmt.Println(args)

	secure = !args["--no-secure"].(bool)
	display = args["--display"].(bool)
	cookieName = args["--cookie-name"].(string)
	acceptedMails := args["--email"].([]string)
	asymetricKey := false

	// provide a quick feedback if the given email contains a pattern error
	emailMatched("test@example.org", acceptedMails)

	b, err := readUserFriendlyFilePath(args["--client-secret-file"].(string))
	if err != nil {
		log.Fatalf("Unable to read client secret file: %v", err)
	}

	// If modifying these scopes, delete your previously saved client_secret.json.
	config, err := google.ConfigFromJSON(b)
	if err != nil {
		log.Fatalf("Unable to parse client secret file to config: %v", err)
	}
	config.Scopes = append(config.Scopes, goauth2.UserinfoEmailScope)

	if count(args["--key"], args["--key-path"], args["--key-env"]) > 1 {
		log.Fatalf("Please provide at most one of --key, --key-path and --key-env arguments")
	}

	keyBytes := []byte(config.ClientSecret)
	if args["--key"] != nil {
		keyBytes = []byte(args["--key"].(string))
	} else if args["--key-env"] != nil {
		name := args["--key-env"].(string)
		value := os.Getenv(name)
		if value == "" {
			log.Fatalf("Failed to read key from environment, variable %s does not exist", name)
		}
		keyBytes = []byte(name)
	} else if args["--key-path"] != nil {
		path := args["--key-path"].(string)
		keyBytes, err = readUserFriendlyFilePath(path)
		if err != nil {
			log.Fatalf("Failed to load private key %s: %v", path, err)
		}
	}
	cookieEncodingKey, err = getPrivateKey(keyBytes)
	if err != nil {
		log.Fatalf("Failed to load private key %v", err)
	}

	switch cookieEncodingKey.(type) {
	case *rsa.PrivateKey:
		log.Printf("Using RSA asymetric encoding method")
		cookieSigningMethod = jwt.SigningMethodRS512
		asymetricKey = true
		cookieDecodingKey = &cookieEncodingKey.(*rsa.PrivateKey).PublicKey
	case *ecdsa.PrivateKey:
		log.Printf("Using ECDSA asymetric encoding method")
		cookieSigningMethod = jwt.SigningMethodES512
		asymetricKey = true
		cookieDecodingKey = &cookieEncodingKey.(*ecdsa.PrivateKey).PublicKey
	case []byte:
		log.Printf("Using HMAC symetric encoding method")
		cookieSigningMethod = jwt.SigningMethodHS512
		cookieDecodingKey = cookieEncodingKey
	default:
		log.Fatalf("Unknown signing method for key %s", cookieEncodingKey)
	}

	tmpl, err := template.New("index").Parse(index)
	if err != nil {
		panic(err)
	}
	redirect := redirectHandler(config)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// / routing catches all as it has no prefix and ends with /
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		c, err := r.Cookie(cookieName)
		if err == nil {
			claims := jwt.StandardClaims{}
			token, err := jwt.ParseWithClaims(c.Value, &claims, func(t *jwt.Token) (interface{}, error) {
				return cookieDecodingKey, nil
			})
			if err == nil {
				if token.Valid {
					w.WriteHeader(http.StatusOK)
					host, _, err := net.SplitHostPort(r.Host)
					if err != nil {
						host = r.Host
					}
					if display {
						tmpl.Execute(w, idx{
							Token: c.Value,
							Netrc: netrc(host, c.Value),
						})
						log.Printf("Provided token for user %s", claims.Id)
					}
					return
				}
				log.Println("Token invalid", token.Method)
			} else {
				log.Println("Failed to parse token:", err)
			}
		}
		redirect(w, r)
	})
	http.HandleFunc("/auth", redirect)
	if asymetricKey && args["--expose-public-key"].(bool) {
		http.HandleFunc("/public_key.pem", func(w http.ResponseWriter, r *http.Request) {
			asn1Bytes, err := x509.MarshalPKIXPublicKey(cookieDecodingKey)
			if err != nil {
				log.Printf("Failed to mashall public key: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			pemkey := &pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: asn1Bytes,
			}
			err = pem.Encode(w, pemkey)
			if err != nil {
				log.Printf("Failed to encode public key PEM: %v", err)
				return
			}
			log.Println("Provided public key")
		})
	}
	http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		state := r.FormValue("state")
		if code := r.FormValue("code"); code != "" {
			email, err := exchangeTokenForEmail(getConfigForRequest(config, r), code)
			if err != nil {
				http.Error(w, "", http.StatusInternalServerError)
				log.Println("state:", state, err)
				return
			}
			if emailMatched(email, acceptedMails) {
				if err := setCookie(w, email, cookieEncodingKey); err != nil {
					http.Error(w, "Forbidden", http.StatusForbidden)
					log.Printf("Access forbidden: unable to generate token: state: %s err: %v", state, err)
				} else {
					w.Header().Set("Location", "/")
					w.WriteHeader(http.StatusFound)
					log.Printf("Generated new token for state: %s email: %s", state, email)
				}
				return
			}
			http.Error(w, "Forbidden", http.StatusForbidden)
			log.Printf("Access forbidden: user %s is not allowed to access the service", email)
		}
		http.Error(w, "", http.StatusBadRequest)
		log.Println("state:", state, "no code")
	})

	addr := args["--listen"].(string)
	log.Fatal(http.ListenAndServe(addr, nil))
}
