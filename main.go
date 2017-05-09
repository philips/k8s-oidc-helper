package main

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/coreos/go-oidc/oauth2"
	"github.com/coreos/go-oidc/oidc"

	flag "github.com/ogier/pflag"
)

const Version = "0.0.1"

var version = flag.BoolP("version", "v", false, "print version and exit")

var oidcClientConfig = oidc.ClientConfig{}

var openBrowser = flag.BoolP("open", "o", true, "Open the oauth approval URL in the browser")

var clientIDFlag = flag.String("client-id", "", "The ClientID for the application")
var clientSecretFlag = flag.String("client-secret", "", "The ClientSecret for the application")
var idpPath = flag.String("idp-path", "", "The path of the identity provider")
var oauthPath = "%s/auth?client_id=tectonic-kubectl&redirect_uri=urn:ietf:wg:oauth:2.0:oob&response_type=code&scope=openid+email+profile+offline_access+groups&state="
var appFile = flag.StringP("config", "c", "", "Path to a json file containing your application's ClientID and ClientSecret. Supercedes the --client-id and --client-secret flags.")

// Get the id_token and refresh_token from google
func getTokens(clientID, clientSecret, code string) (resp oauth2.TokenResponse, err error) {
	client, err := oidc.NewClient(oidcClientConfig)
	if err != nil {
		return
	}

	oauth2Client, err := client.OAuthClient()
	if err != nil {
		return
	}
	return oauth2Client.RequestToken(oauth2.GrantTypeAuthCode, code)
}

func main() {

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	if *version {
		fmt.Printf("k8s-oidc-helper %s\n", Version)
		os.Exit(0)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certPool,
			},
		},
		Timeout: time.Second * 5,
	}

	// oidcClientConfig for logging into console.
	oidcClientConfig = oidc.ClientConfig{
		HTTPClient: httpClient,
		Credentials: oidc.ClientCredentials{
			ID:     *fUserAuthOIDCClientID,
			Secret: *fUserAuthOIDCClientSecret,
		},
		RedirectURL: proxy.SingleJoiningSlash(srv.BaseURL.String(), server.AuthLoginCallbackEndpoint),
		Scope:       []string{"openid", "email", "profile", "groups"},
	}

	var err error
	clientID = *clientIDFlag
	clientSecret = *clientSecretFlag

	if *openBrowser {
		fmt.Printf("Opening this url in your browser: %s\n", fmt.Sprintf(oauthPath, *idpPath, clientID))
		cmd := exec.Command("open", fmt.Sprintf(oauthPath, *idpPath, clientID))
		err = cmd.Start()
	}
	if !*openBrowser || err != nil {
		fmt.Printf("Open this url in your browser: %s\n", fmt.Sprintf(oauthPath, *idpPath, clientID))
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter the code Google gave you: ")
	code, _ := reader.ReadString('\n')
	code = strings.TrimSpace(code)

	token, err := getTokens(clientID, clientSecret, code)
	if err != nil {
		fmt.Printf("Error getting tokens: %s\n", err)
		os.Exit(1)
	}

	buff := new(bytes.Buffer)
	if err := kubeConfigTmpl.Execute(buff, token.IDToken, token.RefreshToken); err != nil {
		fmt.Printf("Error marshaling yaml: %s\n", err)
		os.Exit(1)
	}

	fmt.Println(string(response))
}
