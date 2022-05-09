package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"gopkg.in/yaml.v2"
)

const (
	maxDepth           = 1
	deployFolderPath   = "../../deploy/"
	outputTemplateFile = "../../openshift/template.yaml"
)

var (
	// this holds all of the info that is static in the template. update this as needed
	saasTemplateFile = Template{
		APIVersion: "template.openshift.io/v1",
		Kind:       "Template",
		Metadata: Metadata{
			Name: "configuration-anomaly-detection-template",
		},
		Parameters: []Parameter{
			{Name: "IMAGE_DIGEST", Value: "sha256:22d2a957d935e883f45addd35acc87450ce71ea2f94c33f2df70ff36b015486a"},
			{Name: "REGISTRY_IMG", Value: "quay.io/app-sre/cadctl"},
			{Name: "NAMESPACE_NAME", Value: "configuration-anomaly-detection"},
		},
	}
)

func main() {
	ex, getExecutableErr := os.Executable()
	if getExecutableErr != nil {
		panic(fmt.Errorf("could not get the Executable: %w", getExecutableErr))
	}

	workingDirectory := filepath.Dir(ex)
	fmt.Printf("workingDirectory :: %s\n", workingDirectory)

	var filesNames []string
	relativeDeployFolder := filepath.Join(workingDirectory, deployFolderPath)
	// the max depth is relative to the original folder depth
	initialFolderDepth := strings.Count(relativeDeployFolder, string(os.PathSeparator))

	calculatedMaxDepth := initialFolderDepth + maxDepth
	// get all the yaml files in the deploy folder
	walkErr := filepath.Walk(relativeDeployFolder, findAllYamlFilesInDepth(calculatedMaxDepth, &filesNames))

	if walkErr != nil {
		panic(fmt.Errorf("error while searching files in '%s': %w", relativeDeployFolder, walkErr))
	}

	totalDecodedObjects := 0
	// iterate through each of the files
	for fileIndex, fileName := range filesNames {
		// read the file
		fileName = filepath.Clean(fileName)
		fileAsFileObj, openErr := os.Open(fileName) //#nosec G304 -- This is the best I can do :/

		if openErr != nil {
			panic(fmt.Errorf("could not read file '%s': %w", fileName, openErr))
		}

		yamlDecoder := yaml.NewDecoder(fileAsFileObj)
		yamlDecoder.SetStrict(true)

		fileDecodedObjects := 0
		for {
			// fileAsMap is map[interface{}]interface{} as it's the most general object we can create. if we would have had a stict file k8s format we would have used it
			// it's that and the internal yaml objects are also in that type, so it makes things simpler
			fileAsMap := make(map[interface{}]interface{})
			decodeErr := yamlDecoder.Decode(&fileAsMap)
			// break the loop in case of EOF
			if errors.Is(decodeErr, io.EOF) {
				break
			}
			if decodeErr != nil {
				panic(fmt.Errorf("the file '%s' has decoded '%d' objects (and in general decoded '%d' objects in '%d' files), and failed with: %w",
					fileName,
					fileDecodedObjects,
					totalDecodedObjects,
					fileIndex,
					decodeErr,
				))
			}

			// check it was parsed
			if fileAsMap == nil {
				continue
			}

			removeNestedField(fileAsMap, "metadata", "namespace")

			kind, kindExists := fileAsMap["kind"]
			if !kindExists {
				panic(fmt.Errorf("kind doesn't exist"))
			}

			apiVersion, apiVersionExists := fileAsMap["apiVersion"]
			if !apiVersionExists {
				panic(fmt.Errorf("apiVersion doesn't exist"))
			}

			if apiVersion == "rbac.authorization.k8s.io/v1" && (kind == "RoleBinding" || kind == "ClusterRoleBinding") {
				fixRoleOrClusterRoleBindingErr := fixRoleOrClusterRoleBinding(fileAsMap)
				if fixRoleOrClusterRoleBindingErr != nil {
					panic(fmt.Errorf("fixRoleOrClusterRoleBinding failed: %w", fixRoleOrClusterRoleBindingErr))
				}
			}

			if apiVersion == "tekton.dev/v1beta1" && kind == "Task" {
				fixTaskImageErr := fixTaskImage(fileAsMap)
				if fixTaskImageErr != nil {
					panic(fmt.Errorf("fixTaskImage failed: %w", fixTaskImageErr))
				}
			}

			fileDecodedObjects++

			saasTemplateFile.Objects = append(saasTemplateFile.Objects, fileAsMap)
		}
		totalDecodedObjects += fileDecodedObjects
	}

	// marshal back into bytes
	saasTemplateFileAsBytes, marshalBackErr := yaml.Marshal(&saasTemplateFile)
	if marshalBackErr != nil {
		panic(fmt.Errorf("could not marshal the bigMapping back: %v", marshalBackErr))
	}
	// print to stdout just so we know something happened and the code isn't broken
	fmt.Printf("---\n%s\n", string(saasTemplateFileAsBytes))
	outputFile := filepath.Join(workingDirectory, outputTemplateFile)

	// Open the output file
	outputFile = filepath.Clean(outputFile)
	f, createErr := os.Create(outputFile) //#nosec G304 -- This is the best I can do :/
	if createErr != nil {
		panic(fmt.Errorf("could not create file '%s': %w", outputFile, createErr))
	}

	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			panic(fmt.Errorf("could not close file '%s': %w", outputFile, closeErr))
		}
	}()

	// write the data back into the SAAS file
	_, writeErr := f.Write(saasTemplateFileAsBytes)
	if writeErr != nil {
		panic(fmt.Errorf("could not write marshalled data into file '%s': %w", outputFile, writeErr))
	}
}
func fixRoleOrClusterRoleBinding(fileAsMap map[interface{}]interface{}) error {
	subjects, hasSubjects, getNestedSliceErr := mutableNestedSlice(fileAsMap, "subjects")
	if getNestedSliceErr != nil {
		return fmt.Errorf("error getting subjects: %w", getNestedSliceErr)
	}
	if !hasSubjects {
		return fmt.Errorf("subjects doesn't exist")
	}
	for subjectIndex, subject := range subjects {
		extractedSubject, canConvertExtractedSubject := subject.(map[interface{}]interface{})
		if !canConvertExtractedSubject {
			return fmt.Errorf("could not convert a subject item in index '%d' field into `map[interface{}]interface{}`: '%v'", subjectIndex, reflect.TypeOf(subject))
		}
		delete(extractedSubject, "namespace")
	}
	fileAsMap["subjects"] = subjects
	return nil
}

func fixTaskImage(fileAsMap map[interface{}]interface{}) error {
	steps, hasSteps, getNestedStepsErr := mutableNestedSlice(fileAsMap, "spec", "steps")
	if getNestedStepsErr != nil {
		return fmt.Errorf("error getting steps: %w", getNestedStepsErr)
	}
	if !hasSteps {
		return fmt.Errorf("steps doesn't exist")
	}
	for stepIndex, step := range steps {
		extractedStep, canConvertExtractedStep := step.(map[interface{}]interface{})
		if !canConvertExtractedStep {
			return fmt.Errorf("could not convert a step item in index '%d' field into `map[interface{}]interface{}`: '%v'", stepIndex, reflect.TypeOf(step))
		}
		if extractedStep["name"] != "check-infrastructure" {
			continue
		}
		extractedStep["image"] = "REGISTRY_IMG@IMAGE_DIGEST"
	}
	return nil
}

func findAllYamlFilesInDepth(maxDepth int, filesNames *[]string) func(path string, info os.FileInfo, err error) error {
	return func(path string, info os.FileInfo, err error) error {
		if !strings.HasSuffix(path, "yaml") {
			return nil
		}
		if strings.Count(path, string(os.PathSeparator)) > maxDepth {
			fmt.Printf("skipping file '%s'\n", path)
			return fs.SkipDir
		}
		*filesNames = append(*filesNames, path)
		return nil
	}
}
