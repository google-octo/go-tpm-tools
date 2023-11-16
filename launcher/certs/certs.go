package certs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"

	"github.com/google/go-tpm-tools/launcher/agent"
)

// genCert create a cert for the TEE enviornment
func genCert(vmName string) ([]byte, *ecdsa.PrivateKey, error) {
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

	str1 := string(fingerprint[:])

	token, err := attestAgent.Attest(context.Background(),
		agent.AttestAgentOpts{
			Aud:    peerVM,
			Nonces: []string{str1},
		},
	)
	if err != nil {
		return nil, err
	}

	return token, nil
}
