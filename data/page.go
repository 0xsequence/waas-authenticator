package data

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/0xsequence/waas-authenticator/proto"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type Page struct {
	NextKey map[string]types.AttributeValue
	Limit   int32
}

func PageFromProto(protoPage *proto.Page) (Page, error) {
	page := Page{
		Limit: 25,
	}

	if protoPage != nil {
		if protoPage.Limit > 0 {
			page.Limit = int32(protoPage.Limit)
		}

		if protoPage.After != "" {
			nextKeyString, err := base64.StdEncoding.DecodeString(protoPage.After)
			if err != nil {
				return page, fmt.Errorf("decoding after: %w", err)
			}
			var nextKeyMap map[string]any
			if err := json.Unmarshal(nextKeyString, &nextKeyMap); err != nil {
				return page, fmt.Errorf("unmarshalling next key map: %w", err)
			}
			avMap, err := attributevalue.MarshalMap(nextKeyMap)
			if err != nil {
				return page, fmt.Errorf("marshalling next key map: %w", err)
			}
			page.NextKey = avMap
		}
	}

	return page, nil
}

func (p *Page) ToProto() (*proto.Page, error) {
	protoPage := &proto.Page{Limit: uint32(p.Limit)}
	if p.NextKey != nil {
		nextKeyMap := make(map[string]any, len(p.NextKey))
		if err := attributevalue.UnmarshalMap(p.NextKey, &nextKeyMap); err != nil {
			return nil, err
		}
		b, err := json.Marshal(nextKeyMap)
		if err != nil {
			return nil, err
		}
		protoPage.After = base64.StdEncoding.EncodeToString(b)
	}
	return protoPage, nil
}
