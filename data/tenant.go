package data

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type Tenant struct {
	ProjectID    uint64    `dynamodbav:"ProjectID"`
	Version      int       `dynamodbav:"Version"`
	EncryptedKey []byte    `dynamodbav:"EncryptedKey"`
	Algorithm    string    `dynamodbav:"Algorithm"`
	Ciphertext   []byte    `dynamodbav:"Ciphertext"`
	CreatedAt    time.Time `dynamodbav:"CreatedAt"`
}

// Key returns the Tenant's primary key, consisting of a partition key (ProjectID) and a sort key (Version)
func (t *Tenant) Key() map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"ProjectID": &types.AttributeValueMemberN{Value: strconv.Itoa(int(t.ProjectID))},
		"Version":   &types.AttributeValueMemberN{Value: strconv.Itoa(t.Version)},
	}
}

type TenantTable struct {
	db       DB
	tableARN string
}

func NewTenantTable(db DB, tableARN string) *TenantTable {
	return &TenantTable{db: db, tableARN: tableARN}
}

// Add creates a new Tenant version.
func (t *TenantTable) Add(ctx context.Context, tnt *Tenant) error {
	tnt.CreatedAt = time.Now()

	if tnt.Version == 0 {
		latest, _, err := t.GetLatest(ctx, tnt.ProjectID)
		if err != nil {
			return fmt.Errorf("GetLatest: %w", err)
		}
		if latest != nil {
			tnt.Version = latest.Version + 1
		} else {
			tnt.Version = 1
		}
	}

	av, err := attributevalue.MarshalMap(tnt)
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

// GetLatest returns the latest Tenant version from the DB with the given ProjectID.
//
// Tenant not being found is not considered an error. Instead, it returns `false` as second value if the Tenant
// was not found.
func (t *TenantTable) GetLatest(ctx context.Context, projectID uint64) (*Tenant, bool, error) {
	tnt := Tenant{ProjectID: projectID}
	input := &dynamodb.QueryInput{
		TableName:              aws.String(t.tableARN),
		KeyConditionExpression: aws.String("ProjectID = :id"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":id": &types.AttributeValueMemberN{Value: strconv.Itoa(int(tnt.ProjectID))},
		},
		ScanIndexForward: aws.Bool(false),
		Limit:            aws.Int32(1),
	}

	out, err := t.db.Query(ctx, input)
	if err != nil {
		return nil, false, fmt.Errorf("Query: %w", err)
	}
	if len(out.Items) == 0 || len(out.Items[0]) == 0 {
		return nil, false, nil
	}

	if err := attributevalue.UnmarshalMap(out.Items[0], &tnt); err != nil {
		return nil, false, fmt.Errorf("unmarshal result: %w", err)
	}
	return &tnt, true, nil
}

// GetWithVersion returns the Tenant from the DB with the given ProjectID and version.
//
// Tenant not being found is not considered an error. Instead, it returns `false` as second value if the Tenant
// was not found.
func (t *TenantTable) GetWithVersion(ctx context.Context, projectID uint64, version int) (*Tenant, bool, error) {
	tnt := Tenant{ProjectID: projectID, Version: version}
	input := &dynamodb.GetItemInput{
		TableName: aws.String(t.tableARN),
		Key:       tnt.Key(),
	}

	out, err := t.db.GetItem(ctx, input)
	if err != nil {
		return nil, false, fmt.Errorf("GetItem: %w", err)
	}
	if len(out.Item) == 0 {
		return nil, false, nil
	}

	if err := attributevalue.UnmarshalMap(out.Item, &tnt); err != nil {
		return nil, false, fmt.Errorf("unmarshal result: %w", err)
	}
	return &tnt, true, nil
}
