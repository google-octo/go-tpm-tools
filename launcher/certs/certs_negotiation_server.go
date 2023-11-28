package certs

import (
	"context"
	"log"
)

// a grpc server that will handle incoming cert negotiation
type server struct {
	tcs TeeCertServer
}

// SayHello implements helloworld.GreeterServer
func (s *server) NegotiateCert(ctx context.Context, in *TeeCertNegotiateRequest) (*TeeCertNegotiateResponse, error) {
	log.Printf("Received: %v", in.Cert)
	log.Printf("%v", in.Token)
	return &TeeCertNegotiateResponse{Cert: []byte("mycert"), Token: []byte("mytoken")}, nil
}
