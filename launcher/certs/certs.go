package certs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/go-tpm-tools/launcher/agent"
	"golang.org/x/oauth2"
	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// genCert create a cert for the TEE enviornment
func GenCert(vmName string) ([]byte, *ecdsa.PrivateKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)

	if err != nil {
		return nil, nil, err
	}

	notBefore := time.Now()
	// For now, cert will valid for 7 days
	notAfter := notBefore.Add(7 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: []string{"Google"}, CommonName: vmName},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDer, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	// certPEMblock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDer})
	// keyBytes, err := x509.MarshalECPrivateKey(priv)
	// if err != nil {
	// 	return nil, nil, err
	// }
	// keyPEMblock := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	return certDer, priv, nil

}

// bindCert will get a token and return it with the fingerprint of the cert and audience
// being the other party
func bindCert(cert []byte, peerVM string, attestAgent agent.AttestationAgent) ([]byte, error) {
	// use attestation agent to get a customized audience token
	fingerprint := md5.Sum(cert)

	//
	fmt.Println("BINDINGCERTS")

	hashsum := hex.EncodeToString(fingerprint[:])
	fmt.Println(fingerprint)
	fmt.Println(hashsum)

	// strings.ToValidUTF8()
	fmt.Println("----")

	token, err := attestAgent.Attest(context.Background(),
		agent.AttestAgentOpts{
			Aud:       peerVM,
			Nonces:    []string{hashsum},
			TokenType: "OIDC",
		},
	)
	if err != nil {
		return nil, err
	}

	return token, nil
}

type jwksFile struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	Alg string `json:"alg"`
	Kty string `json:"kty"`
	N   string `json:"n"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	E   string `json:"e"`
}

// verifyCertBinding will very
func verifyCertBinding(cert []byte, tokenBytes []byte) error {
	httpClient := http.Client{}
	// get the jwk for verify token
	// https://confidentialcomputing.googleapis.com/.well-known/openid-configuration
	// https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com
	resp, err := httpClient.Get("https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com")
	if err != nil {
		return err
	}
	jwkbytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read JWK body: %w", err)
	}

	file := jwksFile{} // KEY FILE
	err = json.Unmarshal(jwkbytes, &file)
	if err != nil {
		return fmt.Errorf("failed to unmarshall JWK content: %w", err)

	}
	fmt.Println("KEYFILE: ", file)

	// TODO: Read the token
	claims := jwt.MapClaims{}

	xx, err := parseToken(string(tokenBytes))
	if err != nil {
		return err
	}

	fmt.Println("ACCESS TOKEN", xx.AccessToken)

	// token, parts, err := jwt.Parser.ParseUnverified(tokenString, claims)

	token, err := jwt.ParseWithClaims(string(tokenBytes), &claims, func(token *jwt.Token) (interface{}, error) {
		fmt.Println("my header", token.Header)
		fmt.Println("mykey is", file.Keys[1])

		return getRSAPublicKeyFromJWK(file.Keys[1])
	})
	if err != nil {
		fmt.Println("failed to parse:: ", token)
		return fmt.Errorf("failed to paeeesr, %v", err)
	}

	if !token.Valid {
		return fmt.Errorf("invalid token")
	}

	return nil
}

// getRSAPublicKeyFromJWK extracts a raw RSA public key from a JWK.
func getRSAPublicKeyFromJWK(j jwk) (*rsa.PublicKey, error) {
	// Ensure the key type is RSA.
	if j.Kty != "RSA" {
		return nil, fmt.Errorf("invalid key type: %s", j.Kty)
	}

	// Get the public key components.
	n, err := base64.RawURLEncoding.DecodeString(j.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode 'n': %v", err)
	}
	e, err := base64.RawURLEncoding.DecodeString(j.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode 'n': %v", err)
	}

	e = append([]byte{0}, e...)
	// fmt.Println("-------------", e)
	eee := binary.BigEndian.Uint32(e)
	// eee := binary.Uint64(e)

	fmt.Println(eee)
	ee := int(eee)

	fmt.Println(ee)

	// Construct and return the public key.
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(n),
		E: ee,
	}, nil
}

// initNegotiate will call the peer to establish the cert
func InitNegotiate(peer string, aa agent.AttestationAgent) error {
	conn, err := grpc.Dial(peer, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	defer conn.Close()

	client := NewTeeCertClient(conn)

	xx, _, err := GenCert("myname")
	if err != nil {
		return err
	}

	x, err := bindCert(xx, peer, aa)
	if err != nil {
		return err
	}

	fmt.Println("INIT CERTSSS")

	res, err := client.NegotiateCert(context.Background(), &TeeCertNegotiateRequest{
		Cert: xx, Token: x})

	if err != nil {
		return err
	}

	err = verifyCertBinding(res.Cert, res.Token)
	if err != nil {
		return err
	}

	err = addCertToTrustStore(res.Cert)
	if err != nil {
		return err
	}

	return nil
}

func addCertToTrustStore(cert []byte) error {
	trustStoreFile := "/etc/ssl/certs/ca-certificates.crt"

	trustStoreData, err := os.ReadFile(trustStoreFile)
	if err != nil {
		return err
	}

	trustStoreData = append(trustStoreData, cert...)

	err = os.WriteFile(trustStoreFile, trustStoreData, 0644)
	if err != nil {
		return err
	}

	cmd := exec.Command("update-ca-certificates")

	err = cmd.Run()
	if err != nil {
		return err
	}

	return nil
}

func StartServer() error {
	port := 4111
	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", port))

	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	var opts []grpc.ServerOption

	grpcServer := grpc.NewServer(opts...)

	ss := &server{}

	RegisterTeeCertServer(grpcServer, ss)

	err = grpcServer.Serve(lis)
	if err != nil {
		return err
	}

	return nil
}

// parseToken parses the token ID from the request.
func parseToken(idToken string) (*oauth2.Token, error) {
	// Split the token into its parts.
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("Invalid token format: %s", idToken)
	}

	// Decode the payload.
	payload, err := decodeSegment(parts[1])
	if err != nil {
		return nil, fmt.Errorf("Failed to decode token payload: %v", err)
	}

	// Parse the payload as JSON.
	var payloadMap map[string]interface{}
	if err := json.Unmarshal(payload, &payloadMap); err != nil {
		return nil, fmt.Errorf("Failed to parse token payload: %v", err)
	}

	// Get the token information.
	token := &oauth2.Token{
		AccessToken:  idToken,
		TokenType:    "Bearer",
		RefreshToken: payloadMap["sub"].(string),
		Expiry:       time.Unix(int64(payloadMap["exp"].(float64)), 0),
	}

	return token, nil
}

func decodeSegment(seg string) ([]byte, error) {
	// Pad the segment with '=' characters.
	seg = strings.Replace(seg, "-", "+", -1)
	seg = strings.Replace(seg, "_", "/", -1)
	switch len(seg) % 4 {
	case 0:
	case 2:
		seg += "=="
	case 3:
		seg += "="
	default:
		return nil, fmt.Errorf("Invalid token segment length")
	}

	// Decode the segment.
	data, err := ioutil.ReadAll(base64.NewDecoder(base64.StdEncoding, strings.NewReader(seg)))
	if err != nil {
		return nil, fmt.Errorf("Failed to decode token segment: %v", err)
	}
	return data, nil
}
