// Code generated by smithy-go-codegen DO NOT EDIT.

package ses

import (
	"context"
	"fmt"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// Sets the position of the specified receipt rule in the receipt rule set.
//
// For information about managing receipt rules, see the [Amazon SES Developer Guide].
//
// You can execute this operation no more than once per second.
//
// [Amazon SES Developer Guide]: https://docs.aws.amazon.com/ses/latest/dg/receiving-email-receipt-rules-console-walkthrough.html
func (c *Client) SetReceiptRulePosition(ctx context.Context, params *SetReceiptRulePositionInput, optFns ...func(*Options)) (*SetReceiptRulePositionOutput, error) {
	if params == nil {
		params = &SetReceiptRulePositionInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "SetReceiptRulePosition", params, optFns, c.addOperationSetReceiptRulePositionMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*SetReceiptRulePositionOutput)
	out.ResultMetadata = metadata
	return out, nil
}

// Represents a request to set the position of a receipt rule in a receipt rule
// set. You use receipt rule sets to receive email with Amazon SES. For more
// information, see the [Amazon SES Developer Guide].
//
// [Amazon SES Developer Guide]: https://docs.aws.amazon.com/ses/latest/dg/receiving-email-concepts.html
type SetReceiptRulePositionInput struct {

	// The name of the receipt rule to reposition.
	//
	// This member is required.
	RuleName *string

	// The name of the receipt rule set that contains the receipt rule to reposition.
	//
	// This member is required.
	RuleSetName *string

	// The name of the receipt rule after which to place the specified receipt rule.
	After *string

	noSmithyDocumentSerde
}

// An empty element returned on a successful request.
type SetReceiptRulePositionOutput struct {
	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationSetReceiptRulePositionMiddlewares(stack *middleware.Stack, options Options) (err error) {
	if err := stack.Serialize.Add(&setOperationInputMiddleware{}, middleware.After); err != nil {
		return err
	}
	err = stack.Serialize.Add(&awsAwsquery_serializeOpSetReceiptRulePosition{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsAwsquery_deserializeOpSetReceiptRulePosition{}, middleware.After)
	if err != nil {
		return err
	}
	if err := addProtocolFinalizerMiddlewares(stack, options, "SetReceiptRulePosition"); err != nil {
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
	if err = addTimeOffsetBuild(stack, c); err != nil {
		return err
	}
	if err = addUserAgentRetryMode(stack, options); err != nil {
		return err
	}
	if err = addOpSetReceiptRulePositionValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opSetReceiptRulePosition(options.Region), middleware.Before); err != nil {
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

func newServiceMetadataMiddleware_opSetReceiptRulePosition(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		OperationName: "SetReceiptRulePosition",
	}
}
