package interceptor

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	common "github.com/intelops/go-common/iam/proto/interceptor"
	"github.com/intelops/go-common/logging"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	cerbosclient "github.com/cerbos/cerbos/client"
	ory "github.com/ory/client-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"gopkg.in/yaml.v2"
)

const (
	authorizationHeader = "authorization"
	bearerTokenPrefix   = "Bearer"
)

type Key string

type PolicyConfig struct {
	Exclude               []string `yaml:"exclude"`
	Authenticate          []string `yaml:"authenticate"`
	AuthenticateAuthorize []string `yaml:"authenticate-authorize"`
}
type cerbosClient struct {
	CC cerbosclient.Client // Add any necessary dependencies here
}

type OryClient struct {
	OC        *ory.APIClient
	OryPat    string
	OrySchema string
}

type IAMClient struct {
	IC common.CommonInterceptorServiceClient
}

func newOrySdk(oryUrl string) *ory.APIClient {
	log.Println("creating a ory client")
	config := ory.NewConfiguration()
	config.Servers = ory.ServerConfigurations{{
		URL: oryUrl,
	}}

	return ory.NewAPIClient(config)
}

func NewCerbosClient(cerbosUrl string) (*cerbosClient, error) {
	cli, err := cerbosclient.New(cerbosUrl, cerbosclient.WithPlaintext())
	if err != nil {
		log.Printf("unable to create cerbos client : %v", err)
		return nil, err
	}
	return &cerbosClient{
		CC: cli,
	}, nil
}

func NewOryClient(oryUrl, oryPat, orySchema string) (*OryClient, error) {
	OC := newOrySdk(oryUrl)
	return &OryClient{
		OC:        OC,
		OryPat:    oryPat,
		OrySchema: orySchema,
	}, nil
}

func NewIAMClient(iamaddress string, opts ...grpc.DialOption) (*IAMClient, error) {
	conn, err := grpc.Dial(iamaddress, opts...)
	if err != nil {
		return nil, err
	}
	client := common.NewCommonInterceptorServiceClient(conn)
	return &IAMClient{
		IC: client,
	}, nil
}

type CommonInterceptorConfig struct {
	cerbos         *cerbosClient
	ory            *OryClient
	iam            *IAMClient
	policyLocation string
	logger         logging.Logger
}

func NewCommonInterceptorConfig(iamClient *IAMClient, oryClient *OryClient, policyLocation string) (*CommonInterceptorConfig, error) {
	// Create a logger with the desired configuration
	// Create a logger using the cmni package
	logger := logging.NewLogger()
	return &CommonInterceptorConfig{
		//cerbos:         cerbosClient,
		ory:            oryClient,
		iam:            iamClient,
		policyLocation: policyLocation,
		logger:         logger,
	}, nil
}
func (c *CommonInterceptorConfig) getMetadataFromContext(ctx context.Context) (metadata.MD, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		c.logger.Error("Failed to get metadata from context")
		return nil, status.Error(codes.Unauthenticated, "Failed to get metadata from context")
	}
	return md, nil
}

func (c *CommonInterceptorConfig) authorize(ctx context.Context, accessToken string) (context.Context, error) {
	ctx = context.WithValue(ctx, ory.ContextAccessToken, c.ory.OryPat)
	sessionInfo, _, err := c.ory.OC.IdentityApi.GetSession(ctx, accessToken).Expand([]string{"Identity"}).Execute()
	if err != nil {
		c.logger.Errorf("Error occurred while getting session info for session id: %s: %v", accessToken, err)
		return ctx, status.Errorf(codes.Unauthenticated, "Failed to introspect session id - %v", err)
	}
	c.logger.Infof("session: %s", sessionInfo.Id)
	if !sessionInfo.GetActive() {
		c.logger.Errorf("Error occurred while getting session info for session id: %s", accessToken)
		return ctx, status.Error(codes.Unauthenticated, "session id is not active")
	}
	ctx = context.WithValue(ctx, Key("SESSION_ID"), sessionInfo.Id)
	ctx = context.WithValue(ctx, Key("ORY_ID"), sessionInfo.GetIdentity().Id)
	return ctx, nil
}

func (c *CommonInterceptorConfig) getOrgIdFromContext(ctx context.Context) (string, error) {
	md, err := c.getMetadataFromContext(ctx)
	if err != nil {
		return "", err
	}
	orgid := md.Get("organisationid")
	if len(orgid) == 0 {
		c.logger.Error("No organisation id provided")
		return "", status.Error(codes.Unauthenticated, "No organisation id provided")
	}
	return orgid[0], nil
}

func (c *CommonInterceptorConfig) getTokenFromContext(ctx context.Context) (string, error) {
	md, err := c.getMetadataFromContext(ctx)
	if err != nil {
		return "", err
	}
	bearerToken := md.Get(authorizationHeader)
	if len(bearerToken) == 0 {
		c.logger.Error("No access token provided")
		return "", status.Error(codes.Unauthenticated, "No access token provided")
	}
	splitToken := strings.Split(bearerToken[0], " ")
	if len(splitToken) != 2 || splitToken[0] != bearerTokenPrefix {
		c.logger.Error("Invalid access token")
		return "", status.Error(codes.Unauthenticated, "Invalid access token")
	}
	return splitToken[1], nil
}

func (c *CommonInterceptorConfig) getOryIDFromContext(ctx context.Context) (string, error) {
	oryID := ctx.Value(Key("ORY_ID"))
	if oryID == nil {
		return "", status.Error(codes.Unauthenticated, "Failed to get ory id from context")
	}
	return oryID.(string), nil
}

// readConfig reads the config file and decodes it into Config struct
func (c *CommonInterceptorConfig) readConfig(config *PolicyConfig) error {
	// Read the file location from an environment variable
	fileLocation := c.policyLocation
	if fileLocation == "" {
		fileLocation = "config.yaml"
	}
	// Open the file
	file, err := os.Open(fileLocation)
	if err != nil {
		return err
	}
	// Close the file when we are done
	defer file.Close()
	// Decode the file into our struct
	decoder := yaml.NewDecoder(file)
	err = decoder.Decode(config)
	if err != nil {
		return err
	}
	return nil
}

func contains(slice []string, value string) bool {
	for _, item := range slice {
		if item == value {
			return true
		}
	}
	return false
}

// UnaryInterceptor intercepts the unary RPC and performs authentication and authorizatio
func (ci *CommonInterceptorConfig) UnaryInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	ci.logger.Info("func UnaryInterceptor invoked")
	defer ci.logger.Info("func UnaryInterceptor exited")
	// Read the config from the YAML file
	config := &PolicyConfig{}
	err := ci.readConfig(config)
	if err != nil {
		ci.logger.Errorf("Error occurred while reading config file: %v", err)
		st := status.New(codes.Internal, "Error occurred while reading config file")
		return nil, st.Err()
	}

	// Check if the method is in the Exclude list
	// If the method is in the Exclude list, skip authentication and authorization
	if contains(config.Exclude, info.FullMethod) {
		return handler(ctx, req)
	}
	// Check if the method is in the Authenticate list
	if contains(config.Authenticate, info.FullMethod) {
		// If the method is in the Authenticate list, only check if the session is active
		accessToken, err := ci.getTokenFromContext(ctx)
		if err != nil {
			ci.logger.Errorf("Error occurred while getting session id from context: %v", err)
			st := status.New(codes.Unauthenticated, "Error occurred while getting session id from context")
			return nil, st.Err()
		}

		ctx, err = ci.authorize(ctx, accessToken)
		if err != nil {
			ci.logger.Errorf("Error occurred while authorizing the session id from context: %s: %v", accessToken, err)
			st := status.New(codes.PermissionDenied, "Error occurred while authorizing the session id from context")
			return nil, st.Err()
		}

		return handler(ctx, req)
	}

	// Check if the method is in the AuthenticateAuthorize list
	if contains(config.AuthenticateAuthorize, info.FullMethod) {
		// If the method is in the AuthenticateAuthorize list, check if the session is active and perform authorization logic
		accessToken, err := ci.getTokenFromContext(ctx)
		if err != nil {
			ci.logger.Errorf("Error occurred while getting session id from context: %v", err)
			st := status.New(codes.Unauthenticated, "Error occurred while getting session id from context")
			return nil, st.Err()
		}

		ctx, err = ci.authorize(ctx, accessToken)
		if err != nil {
			ci.logger.Errorf("Error occurred while authorizing the session id from context: %s: %v", accessToken, err)
			st := status.New(codes.PermissionDenied, "Error occurred while authorizing the session id from context")
			return nil, st.Err()
		}
		// Get the metadata from the incoming context
		oryid, err := ci.getOryIDFromContext(ctx)
		if err != nil {
			ci.logger.Errorf("Error occurred while getting ory id from context: %v", err)
			st := status.New(codes.Internal, "Error occurred while getting ory id from context")
			return nil, st.Err()
		}

		orgid, err := ci.getOrgIdFromContext(ctx)
		if err != nil {
			ci.logger.Errorf("Error occurred while getting org id from context: %v", err)
			st := status.New(codes.Internal, "Error occurred while getting org id from context")
			return nil, st.Err()
		}

		// Get actions associated with user in organization using IAM client
		actionsResponse, err := ci.iam.IC.GetActionsWithOryidOrgid(ctx, &common.GetActionsPayload{Oryid: oryid,
			Orgid: orgid})
		if err != nil {
			st := status.New(codes.Internal, "Error occurred while getting actions associated with user in organization using IAM client")
			return nil, st.Err()
		}
		actions := actionsResponse.Actions
		// here instead of roles we are using actions
		principal := cerbosclient.NewPrincipal(actionsResponse.Email,
			actions...)
		// modified := strings.Replace(info.FullMethod, "/", "-", -1)
		// modified = strings.TrimPrefix(modified, "-")
		// if strings.Contains(modified, ".") {
		// 	modified = modified[strings.LastIndex(modified, ".")+1:]
		// }
		// Remove the leading slash
		input := strings.TrimPrefix(info.FullMethod, "/")

		// Replace all slashes with hyphens
		input = strings.ReplaceAll(input, "/", "-")

		// Replace all dots with hyphens
		input = strings.ReplaceAll(input, ".", "-")
		r := cerbosclient.NewResource(input,
			actionsResponse.Email)
		// here for actions we are putting *
		rb := cerbosclient.NewResourceBatch().Add(r, "*")
		resp, err := ci.cerbos.CC.CheckResources(context.Background(), principal, rb)
		if err != nil {
			ci.logger.Errorf("Error occurred while checking resources: %v", err)
			st := status.New(codes.Internal, "Error occurred while checking resources")
			return nil, st.Err()
		}

		res := resp.GetResults()
		fmt.Println("res", res)

		allow := res[0].Actions["*"] == effectv1.Effect_EFFECT_ALLOW

		if allow {
			return handler(ctx, req)
		} else {
			st := status.New(codes.PermissionDenied, "not allowed")
			return nil, st.Err()
		}

	}

	return handler(ctx, req)
}
