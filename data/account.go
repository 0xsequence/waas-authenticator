package data

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/0xsequence/waas-authenticator/proto"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type Account struct {
	// ProjectID is the ID of the Project this Account belongs to
	ProjectID uint64 `dynamodbav:"ProjectID"`

	// Identity is the login method used for this Account, e.g. "oidc:{Issuer}#{Subject}"
	Identity Identity `dynamodbav:"Identity"`

	// UserID is a session address first used by this user prefixed by ProjectID, e.g. "123|0xbC7f8E1bB925ab2c0fCd5A74d0006703AfE702e4"
	UserID string `dynamodbav:"UserID"`

	// Email is optional Email address associated with this Account
	Email string `dynamodbav:"Email"`

	// ProjectScopedEmail is the Email prefixed by ProjectID, e.g. "123|example@sequence.app"
	// It's used as an index partition key to ensure uniqueness within a single tenant only
	ProjectScopedEmail string `dynamodbav:"ProjectScopedEmail"`

	EncryptedKey []byte    `dynamodbav:"EncryptedKey"`
	Algorithm    string    `dynamodbav:"Algorithm"`
	Ciphertext   []byte    `dynamodbav:"Ciphertext"`
	CreatedAt    time.Time `dynamodbav:"CreatedAt"`
}

// Key returns the Session's primary key, consisting of a partition key (ProjectID) and a sort key (ID)
func (a *Account) Key() map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"ProjectID": &types.AttributeValueMemberN{Value: strconv.Itoa(int(a.ProjectID))},
		"Identity":  &types.AttributeValueMemberS{Value: a.Identity.String()},
	}
}

type AccountIndices struct {
	ByUserID string
	ByEmail  string
}

type AccountTable struct {
	db       DB
	tableARN string
	indices  AccountIndices
}

func NewAccountTable(db DB, tableARN string, indices AccountIndices) *AccountTable {
	return &AccountTable{
		db:       db,
		tableARN: tableARN,
		indices:  indices,
	}
}

// Put updates an Account by ProjectID or creates one if it doesn't exist yet.
func (t *AccountTable) Put(ctx context.Context, acct *Account) error {
	acct.CreatedAt = time.Now()

	av, err := attributevalue.MarshalMap(acct)
	if err != nil {
		return fmt.Errorf("marshal input: %w", err)
	}
	input := &dynamodb.PutItemInput{
		TableName: &t.tableARN,
		Item:      av,
	}
	if _, err := t.db.PutItem(ctx, input); err != nil {
		return fmt.Errorf("PutItem: %w", err)
	}
	return nil
}

// Get returns an Account from the DB with the given ProjectID and AccountID
//
// Account not being found is not considered an error. Instead, it returns `false` as second value if the Session
// was not found.
func (t *AccountTable) Get(ctx context.Context, projectID uint64, identity proto.Identity) (*Account, bool, error) {
	acct := Account{ProjectID: projectID, Identity: Identity(identity)}
	input := &dynamodb.GetItemInput{
		TableName: &t.tableARN,
		Key:       acct.Key(),
	}

	out, err := t.db.GetItem(ctx, input)
	if err != nil {
		return nil, false, fmt.Errorf("GetItem: %w", err)
	}
	if len(out.Item) == 0 {
		return nil, false, nil
	}

	if err := attributevalue.UnmarshalMap(out.Item, &acct); err != nil {
		return nil, false, fmt.Errorf("unmarshal result: %w", err)
	}
	return &acct, true, nil
}

// ListByUserID returns all Accounts of a given user.
//
// TODO: implement pagination.
func (t *AccountTable) ListByUserID(ctx context.Context, userID string) ([]*Account, error) {
	input := &dynamodb.QueryInput{
		TableName:              &t.tableARN,
		IndexName:              &t.indices.ByUserID,
		KeyConditionExpression: aws.String("UserID = :userID"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":userID": &types.AttributeValueMemberS{Value: userID},
		},
	}

	out, err := t.db.Query(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("Query: %w", err)
	}

	accounts := make([]*Account, len(out.Items))
	for i, item := range out.Items {
		if err := attributevalue.UnmarshalMap(item, &accounts[i]); err != nil {
			return nil, fmt.Errorf("unmarshal result: %w", err)
		}
	}

	return accounts, nil
}

// ListByEmail returns all Accounts with a given email belonging to a given Project.
//
// TODO: implement pagination.
func (t *AccountTable) ListByEmail(ctx context.Context, projectID uint64, email string) ([]*Account, error) {
	input := &dynamodb.QueryInput{
		TableName:              &t.tableARN,
		IndexName:              &t.indices.ByEmail,
		KeyConditionExpression: aws.String("ProjectScopedEmail = :pse"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pse": &types.AttributeValueMemberS{Value: fmt.Sprintf("%d|%s", projectID, email)},
		},
	}

	out, err := t.db.Query(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("Query: %w", err)
	}

	accounts := make([]*Account, len(out.Items))
	for i, item := range out.Items {
		if err := attributevalue.UnmarshalMap(item, &accounts[i]); err != nil {
			return nil, fmt.Errorf("unmarshal result: %w", err)
		}
	}

	return accounts, nil
}
