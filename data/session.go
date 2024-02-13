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

type Session struct {
	ID           string    `dynamodbav:"ID"`
	ProjectID    uint64    `dynamodbav:"ProjectID"`
	UserID       string    `dynamodbav:"UserID"`
	Identity     string    `dynamodbav:"Identity"`
	FriendlyName string    `dynamodbav:"FriendlyName"`
	EncryptedKey []byte    `dynamodbav:"EncryptedKey"`
	Algorithm    string    `dynamodbav:"Algorithm"`
	Ciphertext   []byte    `dynamodbav:"Ciphertext"`
	RefreshedAt  time.Time `dynamodbav:"RefreshedAt"`
	CreatedAt    time.Time `dynamodbav:"CreatedAt"`
}

// Key returns the Session's primary key, consisting of a partition key (ProjectID) and a sort key (ID)
func (s *Session) Key() map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"ProjectID": &types.AttributeValueMemberN{Value: strconv.Itoa(int(s.ProjectID))},
		"ID":        &types.AttributeValueMemberS{Value: s.ID},
	}
}

type SessionTable struct {
	db            DB
	tableARN      string
	indexByUserID string
}

func NewSessionTable(db DB, tableARN string, indexByUserID string) *SessionTable {
	return &SessionTable{
		db:            db,
		tableARN:      tableARN,
		indexByUserID: indexByUserID,
	}
}

// Put updates a Session by ProjectID or creates one if it doesn't exist yet.
func (t *SessionTable) Put(ctx context.Context, sess *Session) error {
	sess.CreatedAt = time.Now()
	sess.RefreshedAt = time.Now()

	av, err := attributevalue.MarshalMap(sess)
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

// Get returns a Session from the DB with the given ProjectID.
//
// Session not being found is not considered an error. Instead, it returns `false` as second value if the Session
// was not found.
func (t *SessionTable) Get(ctx context.Context, projectID uint64, id string) (*Session, bool, error) {
	sess := Session{ID: id, ProjectID: projectID}
	input := &dynamodb.GetItemInput{
		TableName: aws.String(t.tableARN),
		Key:       sess.Key(),
	}

	out, err := t.db.GetItem(ctx, input)
	if err != nil {
		return nil, false, fmt.Errorf("GetItem: %w", err)
	}
	if len(out.Item) == 0 {
		return nil, false, nil
	}

	if err := attributevalue.UnmarshalMap(out.Item, &sess); err != nil {
		return nil, false, fmt.Errorf("unmarshal result: %w", err)
	}
	return &sess, true, nil
}

// ListByUserID returns all sessions of a given user.
//
// TODO: implement pagination.
func (t *SessionTable) ListByUserID(ctx context.Context, userID string) ([]*Session, error) {
	input := &dynamodb.QueryInput{
		TableName:              &t.tableARN,
		IndexName:              &t.indexByUserID,
		KeyConditionExpression: aws.String("UserID = :userID"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":userID": &types.AttributeValueMemberS{Value: userID},
		},
	}

	out, err := t.db.Query(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("Query: %w", err)
	}

	sessions := make([]*Session, len(out.Items))
	for i, item := range out.Items {
		if err := attributevalue.UnmarshalMap(item, &sessions[i]); err != nil {
			return nil, fmt.Errorf("unmarshal result: %w", err)
		}
	}

	return sessions, nil
}

// ListByProjectID returns all sessions created for a given project.
//
// TODO: implement pagination.
func (t *SessionTable) ListByProjectID(ctx context.Context, projectID uint64) ([]*Session, error) {
	input := &dynamodb.QueryInput{
		TableName:              &t.tableARN,
		KeyConditionExpression: aws.String("ProjectID = :projectID"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":projectID": &types.AttributeValueMemberN{Value: strconv.Itoa(int(projectID))},
		},
	}

	out, err := t.db.Query(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("Query: %w", err)
	}

	sessions := make([]*Session, len(out.Items))
	for i, item := range out.Items {
		if err := attributevalue.UnmarshalMap(item, &sessions[i]); err != nil {
			return nil, fmt.Errorf("unmarshal result: %w", err)
		}
	}

	return sessions, nil
}

// Delete removes a given session from the database.
func (t *SessionTable) Delete(ctx context.Context, projectID uint64, id string) error {
	sess := Session{ID: id, ProjectID: projectID}
	input := &dynamodb.DeleteItemInput{
		Key:       sess.Key(),
		TableName: &t.tableARN,
	}

	if _, err := t.db.DeleteItem(ctx, input); err != nil {
		return fmt.Errorf("DeleteItem: %w", err)
	}
	return nil
}
