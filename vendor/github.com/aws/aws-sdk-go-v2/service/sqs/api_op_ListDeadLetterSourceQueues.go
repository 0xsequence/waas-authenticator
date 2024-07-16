// Code generated by smithy-go-codegen DO NOT EDIT.

package sqs

import (
	"context"
	"fmt"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// Returns a list of your queues that have the RedrivePolicy queue attribute
// configured with a dead-letter queue.
//
// The ListDeadLetterSourceQueues methods supports pagination. Set parameter
// MaxResults in the request to specify the maximum number of results to be
// returned in the response. If you do not set MaxResults , the response includes a
// maximum of 1,000 results. If you set MaxResults and there are additional
// results to display, the response includes a value for NextToken . Use NextToken
// as a parameter in your next request to ListDeadLetterSourceQueues to receive
// the next page of results.
//
// For more information about using dead-letter queues, see [Using Amazon SQS Dead-Letter Queues] in the Amazon SQS
// Developer Guide.
//
// [Using Amazon SQS Dead-Letter Queues]: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-dead-letter-queues.html
func (c *Client) ListDeadLetterSourceQueues(ctx context.Context, params *ListDeadLetterSourceQueuesInput, optFns ...func(*Options)) (*ListDeadLetterSourceQueuesOutput, error) {
	if params == nil {
		params = &ListDeadLetterSourceQueuesInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "ListDeadLetterSourceQueues", params, optFns, c.addOperationListDeadLetterSourceQueuesMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*ListDeadLetterSourceQueuesOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type ListDeadLetterSourceQueuesInput struct {

	// The URL of a dead-letter queue.
	//
	// Queue URLs and names are case-sensitive.
	//
	// This member is required.
	QueueUrl *string

	// Maximum number of results to include in the response. Value range is 1 to 1000.
	// You must set MaxResults to receive a value for NextToken in the response.
	MaxResults *int32

	// Pagination token to request the next set of results.
	NextToken *string

	noSmithyDocumentSerde
}

// A list of your dead letter source queues.
type ListDeadLetterSourceQueuesOutput struct {

	// A list of source queue URLs that have the RedrivePolicy queue attribute
	// configured with a dead-letter queue.
	//
	// This member is required.
	QueueUrls []string

	// Pagination token to include in the next request. Token value is null if there
	// are no additional results to request, or if you did not set MaxResults in the
	// request.
	NextToken *string

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationListDeadLetterSourceQueuesMiddlewares(stack *middleware.Stack, options Options) (err error) {
	if err := stack.Serialize.Add(&setOperationInputMiddleware{}, middleware.After); err != nil {
		return err
	}
	err = stack.Serialize.Add(&awsAwsjson10_serializeOpListDeadLetterSourceQueues{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsAwsjson10_deserializeOpListDeadLetterSourceQueues{}, middleware.After)
	if err != nil {
		return err
	}
	if err := addProtocolFinalizerMiddlewares(stack, options, "ListDeadLetterSourceQueues"); err != nil {
		return fmt.Errorf("add protocol finalizers: %v", err)
	}

	if err = addlegacyEndpointContextSetter(stack, options); err != nil {
		return err
	}
	if err = addSetLoggerMiddleware(stack, options); err != nil {
		return err
	}
	if err = addClientRequestID(stack); err != nil {
		return err
	}
	if err = addComputeContentLength(stack); err != nil {
		return err
	}
	if err = addResolveEndpointMiddleware(stack, options); err != nil {
		return err
	}
	if err = addComputePayloadSHA256(stack); err != nil {
		return err
	}
	if err = addRetry(stack, options); err != nil {
		return err
	}
	if err = addRawResponseToMetadata(stack); err != nil {
		return err
	}
	if err = addRecordResponseTiming(stack); err != nil {
		return err
	}
	if err = addClientUserAgent(stack, options); err != nil {
		return err
	}
	if err = smithyhttp.AddErrorCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = addSetLegacyContextSigningOptionsMiddleware(stack); err != nil {
		return err
	}
	if err = addOpListDeadLetterSourceQueuesValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opListDeadLetterSourceQueues(options.Region), middleware.Before); err != nil {
		return err
	}
	if err = addRecursionDetection(stack); err != nil {
		return err
	}
	if err = addRequestIDRetrieverMiddleware(stack); err != nil {
		return err
	}
	if err = addResponseErrorMiddleware(stack); err != nil {
		return err
	}
	if err = addRequestResponseLogging(stack, options); err != nil {
		return err
	}
	if err = addDisableHTTPSMiddleware(stack, options); err != nil {
		return err
	}
	return nil
}

// ListDeadLetterSourceQueuesAPIClient is a client that implements the
// ListDeadLetterSourceQueues operation.
type ListDeadLetterSourceQueuesAPIClient interface {
	ListDeadLetterSourceQueues(context.Context, *ListDeadLetterSourceQueuesInput, ...func(*Options)) (*ListDeadLetterSourceQueuesOutput, error)
}

var _ ListDeadLetterSourceQueuesAPIClient = (*Client)(nil)

// ListDeadLetterSourceQueuesPaginatorOptions is the paginator options for
// ListDeadLetterSourceQueues
type ListDeadLetterSourceQueuesPaginatorOptions struct {
	// Maximum number of results to include in the response. Value range is 1 to 1000.
	// You must set MaxResults to receive a value for NextToken in the response.
	Limit int32

	// Set to true if pagination should stop if the service returns a pagination token
	// that matches the most recent token provided to the service.
	StopOnDuplicateToken bool
}

// ListDeadLetterSourceQueuesPaginator is a paginator for
// ListDeadLetterSourceQueues
type ListDeadLetterSourceQueuesPaginator struct {
	options   ListDeadLetterSourceQueuesPaginatorOptions
	client    ListDeadLetterSourceQueuesAPIClient
	params    *ListDeadLetterSourceQueuesInput
	nextToken *string
	firstPage bool
}

// NewListDeadLetterSourceQueuesPaginator returns a new
// ListDeadLetterSourceQueuesPaginator
func NewListDeadLetterSourceQueuesPaginator(client ListDeadLetterSourceQueuesAPIClient, params *ListDeadLetterSourceQueuesInput, optFns ...func(*ListDeadLetterSourceQueuesPaginatorOptions)) *ListDeadLetterSourceQueuesPaginator {
	if params == nil {
		params = &ListDeadLetterSourceQueuesInput{}
	}

	options := ListDeadLetterSourceQueuesPaginatorOptions{}
	if params.MaxResults != nil {
		options.Limit = *params.MaxResults
	}

	for _, fn := range optFns {
		fn(&options)
	}

	return &ListDeadLetterSourceQueuesPaginator{
		options:   options,
		client:    client,
		params:    params,
		firstPage: true,
		nextToken: params.NextToken,
	}
}

// HasMorePages returns a boolean indicating whether more pages are available
func (p *ListDeadLetterSourceQueuesPaginator) HasMorePages() bool {
	return p.firstPage || (p.nextToken != nil && len(*p.nextToken) != 0)
}

// NextPage retrieves the next ListDeadLetterSourceQueues page.
func (p *ListDeadLetterSourceQueuesPaginator) NextPage(ctx context.Context, optFns ...func(*Options)) (*ListDeadLetterSourceQueuesOutput, error) {
	if !p.HasMorePages() {
		return nil, fmt.Errorf("no more pages available")
	}

	params := *p.params
	params.NextToken = p.nextToken

	var limit *int32
	if p.options.Limit > 0 {
		limit = &p.options.Limit
	}
	params.MaxResults = limit

	result, err := p.client.ListDeadLetterSourceQueues(ctx, &params, optFns...)
	if err != nil {
		return nil, err
	}
	p.firstPage = false

	prevToken := p.nextToken
	p.nextToken = result.NextToken

	if p.options.StopOnDuplicateToken &&
		prevToken != nil &&
		p.nextToken != nil &&
		*prevToken == *p.nextToken {
		p.nextToken = nil
	}

	return result, nil
}

func newServiceMetadataMiddleware_opListDeadLetterSourceQueues(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		OperationName: "ListDeadLetterSourceQueues",
	}
}
