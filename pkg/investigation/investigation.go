package investigation

// // AwsClient is a wrapper around the aws client, and is used to import the received functions into the Provider
// type ChgmClient = chgm.Client

// // Provider should have all the functions that ChgmService is implementing
// type Provider struct {
// 	// having awsClient and ocmClient this way
// 	// allows for all the method receivers defined on them to be passed into the parent struct,
// 	// thus making it more composable than just having each func redefined here
// 	//
// 	// a different solution is to have the structs have unique names to begin with, which makes the code
// 	// aws.AwsClient feel a bit redundant
// 	ChgmClient
// }

// This will generate mocks for the interfaces in this file
//go:generate mockgen --build_flags=--mod=readonly -source $GOFILE -destination ./mock/interfaces.go -package mock

// Service will wrap all the required commands the client needs to run its operations
type Service interface {
	Triggered() error
	Resolved() error
}

type Client struct {
	Service
}
