// Code generated by smithy-go-codegen DO NOT EDIT.

package ses

import (
	"context"
	"fmt"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/ses/types"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// Creates a configuration set event destination.
//
// When you create or update an event destination, you must provide one, and only
// one, destination. The destination can be CloudWatch, Amazon Kinesis Firehose, or
// Amazon Simple Notification Service (Amazon SNS).
//
// An event destination is the Amazon Web Services service to which Amazon SES
// publishes the email sending events associated with a configuration set. For
// information about using configuration sets, see the [Amazon SES Developer Guide].
//
// You can execute this operation no more than once per second.
//
// [Amazon SES Developer Guide]: https://docs.aws.amazon.com/ses/latest/dg/monitor-sending-activity.html
func (c *Client) CreateConfigurationSetEventDestination(ctx context.Context, params *CreateConfigurationSetEventDestinationInput, optFns ...func(*Options)) (*CreateConfigurationSetEventDestinationOutput, error) {
	if params == nil {
		params = &CreateConfigurationSetEventDestinationInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "CreateConfigurationSetEventDestination", params, optFns, c.addOperationCreateConfigurationSetEventDestinationMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*CreateConfigurationSetEventDestinationOutput)
	out.ResultMetadata = metadata
	return out, nil
}

// Represents a request to create a configuration set event destination. A
// configuration set event destination, which can be either Amazon CloudWatch or
// Amazon Kinesis Firehose, describes an Amazon Web Services service in which
// Amazon SES publishes the email sending events associated with a configuration
// set. For information about using configuration sets, see the [Amazon SES Developer Guide].
//
// [Amazon SES Developer Guide]: https://docs.aws.amazon.com/ses/latest/dg/monitor-sending-activity.html
type CreateConfigurationSetEventDestinationInput struct {

	// The name of the configuration set that the event destination should be
	// associated with.
	//
	// This member is required.
	ConfigurationSetName *string

	// An object that describes the Amazon Web Services service that email sending
	// event where information is published.
	//
	// This member is required.
	EventDestination *types.EventDestination

	noSmithyDocumentSerde
}

// An empty element returned on a successful request.
type CreateConfigurationSetEventDestinationOutput struct {
	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationCreateConfigurationSetEventDestinationMiddlewares(stack *middleware.Stack, options Options) (err error) {
	if err := stack.Serialize.Add(&setOperationInputMiddleware{}, middleware.After); err != nil {
		return err
	}
	err = stack.Serialize.Add(&awsAwsquery_serializeOpCreateConfigurationSetEventDestination{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsAwsquery_deserializeOpCreateConfigurationSetEventDestination{}, middleware.After)
	if err != nil {
		return err
	}
	if err := addProtocolFinalizerMiddlewares(stack, options, "CreateConfigurationSetEventDestination"); err != nil {
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
	if err = addOpCreateConfigurationSetEventDestinationValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opCreateConfigurationSetEventDestination(options.Region), middleware.Before); err != nil {
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

func newServiceMetadataMiddleware_opCreateConfigurationSetEventDestination(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		OperationName: "CreateConfigurationSetEventDestination",
	}
}
