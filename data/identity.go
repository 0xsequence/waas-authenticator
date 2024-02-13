package data

import (
	"fmt"

	"github.com/0xsequence/waas-authenticator/proto"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type Identity proto.Identity

func (id Identity) String() string {
	return proto.Identity(id).String()
}

func (id *Identity) MarshalDynamoDBAttributeValue() (types.AttributeValue, error) {
	s := (*proto.Identity)(id).String()
	if s == "" {
		return nil, fmt.Errorf("invalid identity")
	}
	return &types.AttributeValueMemberS{Value: s}, nil
}

func (id *Identity) UnmarshalDynamoDBAttributeValue(value types.AttributeValue) error {
	v, ok := value.(*types.AttributeValueMemberS)
	if !ok {
		return fmt.Errorf("invalid account ID of type: %T", value)
	}
	return (*proto.Identity)(id).FromString(v.Value)
}
