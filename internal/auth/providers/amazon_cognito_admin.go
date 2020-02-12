package providers

import (
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	awssession "github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/buzzfeed/sso/internal/auth/circuit"
	log "github.com/buzzfeed/sso/internal/pkg/logging"
	"github.com/buzzfeed/sso/internal/pkg/sessions"
	"github.com/datadog/datadog-go/statsd"
)

type CognitoAdminProvider interface {
	ListMemberships(groupName string) (members []string, err error)
	CheckMemberships(userName string) (inGroups []string, err error)
	GlobalSignOut(session *sessions.SessionState) (err error)
}

type CognitoAdminService struct {
	adminService *cognitoidentityprovider.CognitoIdentityProvider
	StatsdClient *statsd.Client
	cb           *circuit.Breaker
	userPoolID   *string
}

func getCognitoIdentityProvider(id, secret, region string) (*cognitoidentityprovider.CognitoIdentityProvider, error) {
	logger := log.NewLogEntry()
	sess, err := awssession.NewSession(&aws.Config{
		Region: aws.String(region),
		Credentials: credentials.NewStaticCredentials(
			id,
			secret,
			""),
	})
	if err != nil {
		logger.WithError(err).Fatal("error creating aws session")
		return nil, err
	}
	idp := cognitoidentityprovider.New(sess)

	return idp, nil
}

func (cas *CognitoAdminService) ListMemberships(groupName string) ([]string, error) {
	var groupMembers []string
	tags := []string{
		"provider:cognito",
		"action:list_members_resource",
		fmt.Sprintf("group:%s", groupName),
	}
	nextToken := ""
	for {
		reqParams := &cognitoidentityprovider.ListUsersInGroupInput{
			GroupName:  &groupName,
			UserPoolId: cas.userPoolID,
		}

		startTS := time.Now()
		req, resp := cas.adminService.ListUsersInGroupRequest(reqParams)
		if nextToken != "" {
			reqParams.SetNextToken(nextToken)
		}
		cas.StatsdClient.Incr("provider.request", tags, 1.0)
		_, err := cas.cb.Call(func() (interface{}, error) {
			return nil, req.Send()
		})
		if err != nil {
			switch e := err.(type) {
			case awserr.Error:
				tags = append(tags, fmt.Sprintf("status_code:%d", req.HTTPResponse.StatusCode))
				cas.StatsdClient.Incr("provider.response", tags, 1.0)
				cas.StatsdClient.Incr("provider.error", tags, 1.0)
				switch e.Code() {
				case cognitoidentityprovider.ErrCodeTooManyRequestsException:
					err = ErrRateLimitExceeded
				case cognitoidentityprovider.ErrCodeInternalErrorException:
					err = ErrServiceUnavailable
				}
			case *circuit.ErrOpenState:
				tags = append(tags, "error:circuit_open")
				cas.StatsdClient.Incr("provider.error", tags, 1.0)
			default:
				tags = append(tags, "error:invalid_response")
				cas.StatsdClient.Incr("provider.internal_error", tags, 1.0)
			}
			return nil, err
		}

		tags = append(tags, fmt.Sprintf("status_code:%d", req.HTTPResponse.StatusCode))
		cas.StatsdClient.Timing("provider.latency", time.Now().Sub(startTS), tags, 1.0)
		cas.StatsdClient.Incr("provider.response", tags, 1.0)

		for _, user := range resp.Users {
			groupMembers = append(groupMembers, *user.Username)
		}

		if resp.NextToken == nil {
			break
		}
		nextToken = *resp.NextToken
	}
	return groupMembers, nil

}

func (cas *CognitoAdminService) CheckMemberships(userName string) ([]string, error) {
	tags := []string{
		"provider:cognito",
		"action:check_memberships_resource",
	}
	inGroups := []string{}

	nextToken := ""
	for {
		reqParams := &cognitoidentityprovider.AdminListGroupsForUserInput{
			Username:   &userName,
			UserPoolId: cas.userPoolID,
		}

		startTS := time.Now()
		req, resp := cas.adminService.AdminListGroupsForUserRequest(reqParams)
		if nextToken != "" {
			reqParams.SetNextToken(nextToken)
		}
		cas.StatsdClient.Incr("provider.request", tags, 1.0)

		_, err := cas.cb.Call(func() (interface{}, error) {
			return nil, req.Send()
		})
		if err != nil {
			switch e := err.(type) {
			case awserr.Error:
				tags = append(tags, fmt.Sprintf("status_code:%d", req.HTTPResponse.StatusCode))
				cas.StatsdClient.Incr("provider.response", tags, 1.0)
				cas.StatsdClient.Incr("provider.error", tags, 1.0)
				switch e.Code() {
				case cognitoidentityprovider.ErrCodeTooManyRequestsException:
					err = ErrRateLimitExceeded
				case cognitoidentityprovider.ErrCodeInternalErrorException:
					err = ErrServiceUnavailable
				}
			case *circuit.ErrOpenState:
				tags = append(tags, "error:circuit_open")
				cas.StatsdClient.Incr("provider.error", tags, 1.0)
			default:
				tags = append(tags, "error:invalid_response")
				cas.StatsdClient.Incr("provider.internal_error", tags, 1.0)
			}
			return nil, err
		}

		tags = append(tags, fmt.Sprintf("status_code:%d", req.HTTPResponse.StatusCode))
		cas.StatsdClient.Timing("provider.latency", time.Now().Sub(startTS), tags, 1.0)
		cas.StatsdClient.Incr("provider.response", tags, 1.0)

		for _, group := range resp.Groups {
			inGroups = append(inGroups, *group.GroupName)
		}

		if resp.NextToken == nil {
			break
		}
		nextToken = *resp.NextToken
	}

	return inGroups, nil
}

func (cas *CognitoAdminService) GlobalSignOut(session *sessions.SessionState) error {
	tags := []string{
		"provider:cognito",
		"action:global_sign_out",
	}

	req, _ := cas.adminService.GlobalSignOutRequest(&cognitoidentityprovider.GlobalSignOutInput{
		AccessToken: &session.AccessToken,
	})

	startTS := time.Now()
	cas.StatsdClient.Incr("provider.request", tags, 1.0)

	_, err := cas.cb.Call(func() (interface{}, error) {
		return nil, req.Send()
	})
	if err != nil {
		switch e := err.(type) {
		case awserr.Error:
			tags = append(tags, fmt.Sprintf("status_code:%d", req.HTTPResponse.StatusCode))
			cas.StatsdClient.Incr("provider.response", tags, 1.0)
			cas.StatsdClient.Incr("provider.error", tags, 1.0)
			switch e.Code() {
			case cognitoidentityprovider.ErrCodeTooManyRequestsException:
				err = ErrRateLimitExceeded
			case cognitoidentityprovider.ErrCodeInternalErrorException:
				err = ErrServiceUnavailable
			}
		case *circuit.ErrOpenState:
			tags = append(tags, "error:circuit_open")
			cas.StatsdClient.Incr("provider.error", tags, 1.0)
		default:
			tags = append(tags, "error:invalid_response")
			cas.StatsdClient.Incr("provider.internal_error", tags, 1.0)
		}
		return err
	}

	tags = append(tags, fmt.Sprintf("status_code:%d", req.HTTPResponse.StatusCode))
	cas.StatsdClient.Timing("provider.latency", time.Now().Sub(startTS), tags, 1.0)
	cas.StatsdClient.Incr("provider.response", tags, 1.0)

	return nil
}
