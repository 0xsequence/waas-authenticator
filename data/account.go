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

// Create creates a new Account or fails if it already exists.
func (t *AccountTable) Create(ctx context.Context, acct *Account) error {
	acct.CreatedAt = time.Now()

	av, err := attributevalue.MarshalMap(acct)
	if err != nil {
		return fmt.Errorf("marshal input: %w", err)
	}
	input := &dynamodb.PutItemInput{
		TableName:           &t.tableARN,
		Item:                av,
		ConditionExpression: aws.String("attribute_not_exists(#I)"),
		ExpressionAttributeNames: map[string]string{
			"#I": "Identity",
		},
	}
	if _, err := t.db.PutItem(ctx, input); err != nil {
		return fmt.Errorf("PutItem: %w", err)
	}
	return nil
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

func (t *AccountTable) Delete(ctx context.Context, projectID uint64, identity proto.Identity) error {
	acct := Account{ProjectID: projectID, Identity: Identity(identity)}
	input := &dynamodb.DeleteItemInput{
		TableName: &t.tableARN,
		Key:       acct.Key(),
	}

	_, err := t.db.DeleteItem(ctx, input)
	if err != nil {
		return err
	}
	return nil
}

func (t *AccountTable) ListByProjectAndIdentity(ctx context.Context, page Page, projectID uint64, identityType proto.IdentityType, issuer string) ([]*Account, Page, error) {
	if page.Limit <= 0 {
		page.Limit = 25
	}
	if page.Limit > 100 {
		page.Limit = 100
	}

	input := &dynamodb.QueryInput{
		TableName:              &t.tableARN,
		KeyConditionExpression: aws.String("#P = :projectID"),
		ExpressionAttributeNames: map[string]string{
			"#P": "ProjectID",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":projectID": &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", projectID)},
		},
		Limit:             &page.Limit,
		ExclusiveStartKey: page.NextKey,
	}

	var identCond string
	if identityType != proto.IdentityType_None {
		identCond = string(identityType) + ":"
		if issuer != "" {
			identCond += issuer
		}

		*input.KeyConditionExpression += " and begins_with(#I, :identCond)"
		input.ExpressionAttributeNames["#I"] = "Identity"
		input.ExpressionAttributeValues[":identCond"] = &types.AttributeValueMemberS{Value: identCond}
	}

	out, err := t.db.Query(ctx, input)
	if err != nil {
		return nil, page, fmt.Errorf("Query: %w", err)
	}

	accounts := make([]*Account, len(out.Items))
	for i, item := range out.Items {
		if err := attributevalue.UnmarshalMap(item, &accounts[i]); err != nil {
			return nil, page, fmt.Errorf("unmarshal result: %w", err)
		}
	}

	page.NextKey = out.LastEvaluatedKey
	return accounts, page, nil
}

func (t *AccountTable) GetBatch(ctx context.Context, projectID uint64, identities []proto.Identity) ([]*Account, error) {
	keys := make([]map[string]types.AttributeValue, len(identities))
	for i, identity := range identities {
		acct := Account{ProjectID: projectID, Identity: Identity(identity)}
		keys[i] = acct.Key()
	}

	input := &dynamodb.BatchGetItemInput{
		RequestItems: map[string]types.KeysAndAttributes{
			t.tableARN: {Keys: keys},
		},
	}

	out, err := t.db.BatchGetItem(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("BatchGetItem: %w", err)
	}

	for _, results := range out.Responses {
		accounts := make([]*Account, len(results))
		for i, item := range results {
			if err := attributevalue.UnmarshalMap(item, &accounts[i]); err != nil {
				return nil, fmt.Errorf("unmarshal result: %w", err)
			}
		}
		return accounts, nil
	}

	return make([]*Account, 0), nil
}
