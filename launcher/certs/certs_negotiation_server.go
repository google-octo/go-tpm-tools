package certs

import (
	"context"
	"log"

	"github.com/google/go-tpm-tools/launcher/agent"
	"google.golang.org/grpc/peer"
)

// a grpc server that will handle incoming cert negotiation
type server struct {
	UnimplementedTeeCertServer
	mycert  []byte
	attesta agent.AttestationAgent
}

// NegotiateCert implements TeeCertServer.NegotiateCert
// Receives request from another peer, after verifying issue the cert
func (s *server) NegotiateCert(ctx context.Context, in *TeeCertNegotiateRequest) (*TeeCertNegotiateResponse, error) {
	log.Printf("Received CERT: %v", string(in.Cert))
	log.Printf("Token: %v", string(in.Token))

	err := verifyCertBinding(in.Cert, in.Token)
	if err != nil {
		return nil, err
	}

	// addition verification
	// dns and ip address, addtion claims verify here etc...

	// store the cert into trust store
	addCertToTrustStore(in.Cert)

	// get peer host
	p, _ := peer.FromContext(ctx)
	log.Println("peer addr ", p.Addr.String())
	log.Println("peer network", p.Addr.Network())
	// log.Println("peer authtype", p.AuthInfo)

	// get token, prepare my own token
	token, err := bindCert(s.mycert, p.Addr.String(), s.attesta)
	if err != nil {
		return nil, err
	}

	// replying my cert to the peer
	return &TeeCertNegotiateResponse{Cert: s.mycert, Token: token}, nil
}
