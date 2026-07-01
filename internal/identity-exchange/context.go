package identityexchange

import (
	"context"

	"google.golang.org/grpc/metadata"
)

type identityExchangeContextKey struct{}

const (
	metadataIDExchangeTokenKey = "identity-exchange-token"
)

func NewContextWithIDExchangeToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, identityExchangeContextKey{}, token)
}

func IDExchangeTokenFromContext(ctx context.Context) string {
	jwtToken, _ := ctx.Value(identityExchangeContextKey{}).(string)
	return jwtToken
}

func AppendTokenToOutgoingContext(ctx context.Context, jwtToken string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, metadataIDExchangeTokenKey, jwtToken)
}
