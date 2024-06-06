package data

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/0xsequence/go-sequence/intents"
	"github.com/0xsequence/waas-authenticator/proto"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type AuthID struct {
	ProjectID    uint64
	IdentityType intents.IdentityType
	Verifier     string
}

func (id AuthID) String() string {
	return fmt.Sprintf("%d/%s/%s", id.ProjectID, id.IdentityType, id.Verifier)
}

func (id *AuthID) FromString(s string) error {
	parts := strings.SplitN(s, "/", 3)
	if len(parts) != 3 {
		return fmt.Errorf("invalid auth session ID format: %s", s)
	}

	projID, err := strconv.Atoi(parts[0])
	if err != nil {
		return fmt.Errorf("invalid project ID: %s", s)
	}

	id.ProjectID = uint64(projID)
	id.IdentityType = intents.IdentityType(parts[1])
	id.Verifier = parts[2]
	return nil
}

func (id *AuthID) MarshalDynamoDBAttributeValue() (types.AttributeValue, error) {
	return &types.AttributeValueMemberS{Value: id.String()}, nil
}

func (id *AuthID) UnmarshalDynamoDBAttributeValue(value types.AttributeValue) error {
	v, ok := value.(*types.AttributeValueMemberS)
	if !ok {
		return fmt.Errorf("invalid auth session ID of type: %T", value)
	}
	return id.FromString(v.Value)
}

type VerificationContext struct {
	ID           AuthID    `dynamodbav:"ID"`
	EncryptedKey []byte    `dynamodbav:"EncryptedKey"`
	Algorithm    string    `dynamodbav:"Algorithm"`
	Ciphertext   []byte    `dynamodbav:"Ciphertext"`
	CreatedAt    time.Time `dynamodbav:"CreatedAt"`
}

func (s *VerificationContext) Key() map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"ID": &types.AttributeValueMemberS{Value: s.ID.String()},
	}
}

func (s *VerificationContext) CorrespondsTo(data *proto.VerificationContext) bool {
	if string(s.ID.IdentityType) != string(data.IdentityType) {
		return false
	}
	if s.ID.Verifier != data.Verifier {
		return false
	}
	if s.ID.ProjectID != data.ProjectID {
		return false
	}
	return true
}

type VerificationContextTable struct {
	db       DB
	tableARN string
}

func NewVerificationContextTable(db DB, tableARN string) *VerificationContextTable {
	return &VerificationContextTable{
		db:       db,
		tableARN: tableARN,
	}
}

// Put updates a VerificationContext by ID or creates one if it doesn't exist yet.
func (t *VerificationContextTable) Put(ctx context.Context, verifCtx *VerificationContext) error {
	verifCtx.CreatedAt = time.Now()

	av, err := attributevalue.MarshalMap(verifCtx)
	if err != nil {
		return fmt.Errorf("marshal input: %w", err)
	}
	input := &dynamodb.PutItemInput{
		TableName: aws.String(t.tableARN),
		Item:      av,
	}
	if _, err := t.db.PutItem(ctx, input); err != nil {
		return fmt.Errorf("PutItem: %w", err)
	}
	return nil
}

// Get returns an AuthSession from the DB with the given ID.
//
// AuthSession not being found is not considered an error. Instead, it returns `false` as second value if the AuthSession
// was not found.
func (t *VerificationContextTable) Get(ctx context.Context, id AuthID) (*VerificationContext, bool, error) {
	verifCtx := VerificationContext{ID: id}
	input := &dynamodb.GetItemInput{
		TableName: aws.String(t.tableARN),
		Key:       verifCtx.Key(),
	}

	out, err := t.db.GetItem(ctx, input)
	if err != nil {
		return nil, false, fmt.Errorf("GetItem: %w", err)
	}
	if len(out.Item) == 0 {
		return nil, false, nil
	}

	if err := attributevalue.UnmarshalMap(out.Item, &verifCtx); err != nil {
		return nil, false, fmt.Errorf("unmarshal result: %w", err)
	}
	return &verifCtx, true, nil
}

func (t *VerificationContextTable) UpdateData(
	ctx context.Context, current *VerificationContext, encryptedKey []byte, algorithm string, ciphertext []byte,
) error {
	oldEncryptedKey := current.EncryptedKey
	oldAlgorithm := current.Algorithm
	oldCiphertext := current.Ciphertext

	current.EncryptedKey = encryptedKey
	current.Algorithm = algorithm
	current.Ciphertext = ciphertext

	av, err := attributevalue.MarshalMap(current)
	if err != nil {
		return fmt.Errorf("marshal input: %w", err)
	}
	input := &dynamodb.PutItemInput{
		TableName: aws.String(t.tableARN),
		Item:      av,
		ConditionExpression: aws.String(
			"attribute_exists(ID) AND EncryptedKey = :encrypted_key AND Algorithm = :algorithm AND Ciphertext = :ciphertext",
		),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":encrypted_key": &types.AttributeValueMemberB{Value: oldEncryptedKey},
			":algorithm":     &types.AttributeValueMemberS{Value: oldAlgorithm},
			":ciphertext":    &types.AttributeValueMemberB{Value: oldCiphertext},
		},
	}
	if _, err := t.db.PutItem(ctx, input); err != nil {
		return fmt.Errorf("UpdateData: %w", err)
	}
	return nil
}
