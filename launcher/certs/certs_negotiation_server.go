package certs

import (
	"context"
	"log"
)

// a grpc server that will handle incoming cert negotiation
type server struct {
	UnimplementedTeeCertServer
}

// NegotiateCert implements TeeCertServer.NegotiateCert
// Receives request from another peer, after verifying
func (s *server) NegotiateCert(ctx context.Context, in *TeeCertNegotiateRequest) (*TeeCertNegotiateResponse, error) {
	log.Printf("Received: %v", in.Cert)
	log.Printf("%v", in.Token)

	err := verifyCertBinding(in.Cert, in.Token)
	if err != nil {
		return nil, err
	}

	return &TeeCertNegotiateResponse{Cert: []byte("mycert"), Token: []byte("mytoken")}, nil
}
