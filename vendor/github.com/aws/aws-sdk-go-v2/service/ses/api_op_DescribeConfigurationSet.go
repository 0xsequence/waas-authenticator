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

// Returns the details of the specified configuration set. For information about
// using configuration sets, see the [Amazon SES Developer Guide].
//
// You can execute this operation no more than once per second.
//
// [Amazon SES Developer Guide]: https://docs.aws.amazon.com/ses/latest/dg/monitor-sending-activity.html
func (c *Client) DescribeConfigurationSet(ctx context.Context, params *DescribeConfigurationSetInput, optFns ...func(*Options)) (*DescribeConfigurationSetOutput, error) {
	if params == nil {
		params = &DescribeConfigurationSetInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "DescribeConfigurationSet", params, optFns, c.addOperationDescribeConfigurationSetMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*DescribeConfigurationSetOutput)
	out.ResultMetadata = metadata
	return out, nil
}

// Represents a request to return the details of a configuration set.
// Configuration sets enable you to publish email sending events. For information
// about using configuration sets, see the [Amazon SES Developer Guide].
//
// [Amazon SES Developer Guide]: https://docs.aws.amazon.com/ses/latest/dg/monitor-sending-activity.html
type DescribeConfigurationSetInput struct {

	// The name of the configuration set to describe.
	//
	// This member is required.
	ConfigurationSetName *string

	// A list of configuration set attributes to return.
	ConfigurationSetAttributeNames []types.ConfigurationSetAttribute

	noSmithyDocumentSerde
}

// Represents the details of a configuration set. Configuration sets enable you to
// publish email sending events. For information about using configuration sets,
// see the [Amazon SES Developer Guide].
//
// [Amazon SES Developer Guide]: https://docs.aws.amazon.com/ses/latest/dg/monitor-sending-activity.html
type DescribeConfigurationSetOutput struct {

	// The configuration set object associated with the specified configuration set.
	ConfigurationSet *types.ConfigurationSet

	// Specifies whether messages that use the configuration set are required to use
	// Transport Layer Security (TLS).
	DeliveryOptions *types.DeliveryOptions

	// A list of event destinations associated with the configuration set.
	EventDestinations []types.EventDestination

	// An object that represents the reputation settings for the configuration set.
	ReputationOptions *types.ReputationOptions

	// The name of the custom open and click tracking domain associated with the
	// configuration set.
	TrackingOptions *types.TrackingOptions

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationDescribeConfigurationSetMiddlewares(stack *middleware.Stack, options Options) (err error) {
	if err := stack.Serialize.Add(&setOperationInputMiddleware{}, middleware.After); err != nil {
		return err
	}
	err = stack.Serialize.Add(&awsAwsquery_serializeOpDescribeConfigurationSet{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsAwsquery_deserializeOpDescribeConfigurationSet{}, middleware.After)
	if err != nil {
		return err
	}
	if err := addProtocolFinalizerMiddlewares(stack, options, "DescribeConfigurationSet"); err != nil {
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
	if err = addOpDescribeConfigurationSetValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opDescribeConfigurationSet(options.Region), middleware.Before); err != nil {
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

func newServiceMetadataMiddleware_opDescribeConfigurationSet(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		OperationName: "DescribeConfigurationSet",
	}
}
