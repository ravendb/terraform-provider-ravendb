package ravendb

import (
	"errors"
	"fmt"
	"github.com/gruntwork-io/terratest/modules/terraform"
	test_structure "github.com/gruntwork-io/terratest/modules/test-structure"
	"github.com/ravendb/ravendb-go-client"
	"github.com/ravendb/ravendb-go-client/serverwide/operations"
	internal_operations "github.com/ravendb/terraform-provider-ravendb/operations"
	"os"
	"strconv"
	"testing"
)

type AWSCredentials struct {
	AccessKey string
	SecretKey string
}

func checkTfFolderEnv() error {
	if os.Getenv("TF_FOLDER") == "" {
		return errors.New("`TF_FOLDER` must be set for acceptance testing")
	}
	return nil
}

func checkAwsEnv() error {
	if os.Getenv("AWS_ACCESS_KEY_ID") == "" || os.Getenv("AWS_SECRET_ACCESS_KEY") == "" {
		return errors.New("`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` must be set for acceptance testing")
	}
	return nil
}

func GetAWSCredentialsFromEnv() AWSCredentials {
	return AWSCredentials{
		AccessKey: os.Getenv("AWS_ACCESS_KEY_ID"),
		SecretKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
	}
}

func Test_Should_Init_Apply_Ping_CreateData_Destroy(t *testing.T) {
	err := checkAwsEnv()
	if err != nil {
		t.Fatal(err)
	}

	err = checkTfFolderEnv()
	if err != nil {
		t.Fatal(err)
	}

	terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
		TerraformDir: os.Getenv("TF_FOLDER"),
		EnvVars: map[string]string{
			"AWS_ACCESS_KEY_ID":     GetAWSCredentialsFromEnv().AccessKey,
			"AWS_SECRET_ACCESS_KEY": GetAWSCredentialsFromEnv().SecretKey,
		},
	})

	terraform.InitAndApply(t, terraformOptions)

	test_structure.RunTestStage(t, "validate", func() {
		err := testClusterConnectivity(t, terraformOptions)
		if err != nil {
			t.Fatal(err)
		}

		err = testCreateSampleData(t, terraformOptions)
		if err != nil {
			t.Fatal(err)
		}

		terraform.Destroy(t, terraformOptions)

		err = cleanUpState()
		if err != nil {
			t.Fatal(err)
		}
	})

}

func testClusterConnectivity(t *testing.T, options *terraform.Options) error {
	var host string

	nodes := terraform.OutputList(t, options, "public_instance_ips")
	host = nodes[0]
	serverNode := []string{host}
	store := ravendb.NewDocumentStore(serverNode, "")

	if err := store.Initialize(); err != nil {
		return err
	}

	operation := internal_operations.OperationPingToNode{}

	err := executeWithRetries(store, &operation)
	if err != nil {
		return err
	}

	clusterTopology := operations.OperationGetClusterTopology{}
	err = executeWithRetries(store, &clusterTopology)
	if err != nil {
		return err
	}

	if len(clusterTopology.Topology.Members) != len(operation.Result) {
		return errors.New("received number of nodes:" + strconv.Itoa(len(operation.Result)) + " while pinging is not equal to number of nodes existing in the cluster:" + strconv.Itoa(len(clusterTopology.Topology.Members)))
	}

	for _, nodeResult := range operation.Result {
		if nodeResult.Error != "" {
			return errors.New(nodeResult.Error)
		}
	}

	fmt.Println("==> done pinging cluster nodes")
	return nil
}

func testCreateSampleData(t *testing.T, options *terraform.Options) error {
	var host string

	nodes := terraform.OutputList(t, options, "public_instance_ips")
	dbName := terraform.Output(t, options, "database_name")
	host = nodes[0]
	serverNode := []string{host}

	store := ravendb.NewDocumentStore(serverNode, dbName)
	if err := store.Initialize(); err != nil {
		return err
	}

	operation := ravendb.CreateSampleDataOperation{}
	err := executeWithRetriesMaintenanceOperations(store, &operation)

	if err != nil {
		return err
	}

	fmt.Println("==> done creating sample data")
	return nil
}

func cleanUpState() error {
	var err = os.Remove(os.Getenv("TF_FOLDER") + "\\terraform.tfstate")
	if err != nil {
		return err
	}

	err = os.Remove(os.Getenv("TF_FOLDER") + "\\terraform.tfstate.backup")
	if err != nil {
		return err
	}

	err = os.Remove(os.Getenv("TF_FOLDER") + "\\.terraform.lock.hcl")
	if err != nil {
		return err
	}

	fmt.Println("==> done deleting state files")
	return nil
}
