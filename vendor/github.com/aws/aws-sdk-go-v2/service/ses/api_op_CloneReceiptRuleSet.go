// Code generated by smithy-go-codegen DO NOT EDIT.

package ses

import (
	"context"
	"fmt"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// Creates a receipt rule set by cloning an existing one. All receipt rules and
// configurations are copied to the new receipt rule set and are completely
// independent of the source rule set.
//
// For information about setting up rule sets, see the [Amazon SES Developer Guide].
//
// You can execute this operation no more than once per second.
//
// [Amazon SES Developer Guide]: https://docs.aws.amazon.com/ses/latest/dg/receiving-email-concepts.html#receiving-email-concepts-rules
func (c *Client) CloneReceiptRuleSet(ctx context.Context, params *CloneReceiptRuleSetInput, optFns ...func(*Options)) (*CloneReceiptRuleSetOutput, error) {
	if params == nil {
		params = &CloneReceiptRuleSetInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "CloneReceiptRuleSet", params, optFns, c.addOperationCloneReceiptRuleSetMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*CloneReceiptRuleSetOutput)
	out.ResultMetadata = metadata
	return out, nil
}

// Represents a request to create a receipt rule set by cloning an existing one.
// You use receipt rule sets to receive email with Amazon SES. For more
// information, see the [Amazon SES Developer Guide].
//
// [Amazon SES Developer Guide]: https://docs.aws.amazon.com/ses/latest/dg/receiving-email-concepts.html
type CloneReceiptRuleSetInput struct {

	// The name of the rule set to clone.
	//
	// This member is required.
	OriginalRuleSetName *string

	// The name of the rule set to create. The name must meet the following
	// requirements:
	//
	//   - Contain only ASCII letters (a-z, A-Z), numbers (0-9), underscores (_), or
	//   dashes (-).
	//
	//   - Start and end with a letter or number.
	//
	//   - Contain 64 characters or fewer.
	//
	// This member is required.
	RuleSetName *string

	noSmithyDocumentSerde
}

// An empty element returned on a successful request.
type CloneReceiptRuleSetOutput struct {
	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationCloneReceiptRuleSetMiddlewares(stack *middleware.Stack, options Options) (err error) {
	if err := stack.Serialize.Add(&setOperationInputMiddleware{}, middleware.After); err != nil {
		return err
	}
	err = stack.Serialize.Add(&awsAwsquery_serializeOpCloneReceiptRuleSet{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsAwsquery_deserializeOpCloneReceiptRuleSet{}, middleware.After)
	if err != nil {
		return err
	}
	if err := addProtocolFinalizerMiddlewares(stack, options, "CloneReceiptRuleSet"); err != nil {
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
	if err = addOpCloneReceiptRuleSetValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opCloneReceiptRuleSet(options.Region), middleware.Before); err != nil {
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

func newServiceMetadataMiddleware_opCloneReceiptRuleSet(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		OperationName: "CloneReceiptRuleSet",
	}
}
