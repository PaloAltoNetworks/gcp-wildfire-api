// ############################################################################################
// Copyright 2021 Palo Alto Networks.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ############################################################################################

package wildfire_api_demo

import (
	"bytes"
	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	storage "cloud.google.com/go/storage"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// GCSEvent is the payload of a GCS event.
type GCSEvent struct {
	Kind                    string                 `json:"kind"`
	ID                      string                 `json:"id"`
	SelfLink                string                 `json:"selfLink"`
	Name                    string                 `json:"name"`
	Bucket                  string                 `json:"bucket"`
	Generation              string                 `json:"generation"`
	Metageneration          string                 `json:"metageneration"`
	ContentType             string                 `json:"contentType"`
	TimeCreated             time.Time              `json:"timeCreated"`
	Updated                 time.Time              `json:"updated"`
	TemporaryHold           bool                   `json:"temporaryHold"`
	EventBasedHold          bool                   `json:"eventBasedHold"`
	RetentionExpirationTime time.Time              `json:"retentionExpirationTime"`
	StorageClass            string                 `json:"storageClass"`
	TimeStorageClassUpdated time.Time              `json:"timeStorageClassUpdated"`
	Size                    string                 `json:"size"`
	MD5Hash                 string                 `json:"md5Hash"`
	MediaLink               string                 `json:"mediaLink"`
	ContentEncoding         string                 `json:"contentEncoding"`
	ContentDisposition      string                 `json:"contentDisposition"`
	CacheControl            string                 `json:"cacheControl"`
	Metadata                map[string]interface{} `json:"metadata"`
	CRC32C                  string                 `json:"crc32c"`
	ComponentCount          int                    `json:"componentCount"`
	Etag                    string                 `json:"etag"`
	CustomerEncryption      struct {
		EncryptionAlgorithm string `json:"encryptionAlgorithm"`
		KeySha256           string `json:"keySha256"`
	}
	KMSKeyName    string `json:"kmsKeyName"`
	ResourceState string `json:"resourceState"`
}

// Wildfire verdict response object
type wildfireVerdict struct {
	Sha256  string `xml:"get-verdict-info>sha256"`
	Verdict string `xml:"get-verdict-info>verdict"`
	Md5     string `xml:"get-verdict-info>md5"`
	Error   string `xml:"error-message"`
}

// Wildfire upload response object
type wildfireUpload struct {
	Error string `xml:"error-message"`
}

// Gets a secret from the Google Secrets Manager and returns it as a string
//   name format projects/project-id/secrets/secret-name/versions/latest
func getSecretValue(name string) string {
	// Create the client.
	ctx := context.Background()
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		log.Fatalln("failed to create secret manager client", err)
	}
	defer client.Close()

	// Build the request.
	req := &secretmanagerpb.AccessSecretVersionRequest{
		Name: name,
	}

	// Call the API.
	result, err := client.AccessSecretVersion(ctx, req)
	if err != nil {
		log.Fatalln("failed to access secret version", name, err)
	}

	return string(result.Payload.Data)
}

// Check MD5 Hash in Wildfire Database
//   Returns error and verdict result
func checkWildfireVerdictByMD5(md5Hash string) string {

	// get GCP project value from environmental variables
	projectId := os.Getenv("GCP_PROJECT")

	// get wildfire api portal and key from GCP secrets manager
	wildfire_api_portal := getSecretValue("projects/" + projectId + "/secrets/wildfire_api_portal/versions/latest")
	wildfire_api_key := getSecretValue("projects/" + projectId + "/secrets/wildfire_api_key/versions/latest")

	// make api call to wildfire to get verdict
	data := url.Values{}
	data.Set("apikey", wildfire_api_key)
	data.Set("hash", md5Hash)

	fullURL := "https://" + wildfire_api_portal + "/publicapi/get/verdict"

	resp, err := http.PostForm(fullURL, data)
	if err != nil {
		log.Fatal(err)
	}

	defer resp.Body.Close()

	var verdict wildfireVerdict

	ByteValue, _ := ioutil.ReadAll(resp.Body)

	err = xml.Unmarshal(ByteValue, &verdict)
	if err != nil {
		fmt.Println(err)
	}

	// check for all possible verdict responses
	switch verdict.Verdict {
	case "0":
		return "benign"
	case "1":
		return "malware"
	case "2":
		return "grayware"
	case "4":
		return "phishing"
	case "5":
		return "c2"
	case "-100":
		return "pending, the sample exists, but there is currently no verdict (applicable to file analysis only)"
	case "-101":
		return "unknown - error -101"
	case "-102":
		return "unknown - cannot find sample record in the database"
	case "-103":
		return "unknown - invalid hash value"
	default:
		return "unknown - no verdict"
	}

	return "" // Return No Error
}

// decode the GCS md5 value to a MD5 hash string
func decodeGCSMD5Value(str string) string {
	data, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		fmt.Println("error:", err)
		return ""
	}
	x := hex.EncodeToString(data)
	if err != nil {
		fmt.Println(err)
		panic(err)
	}
	return x
}

// upload file contents to wildfire for analysis
func uploadFileToWildfire(filename, contents string) error {

	// get GCP project value from environmental variables
	projectId := os.Getenv("GCP_PROJECT")

	// get wildfire api portal and key from GCP secrets manager
	wildfire_api_portal := getSecretValue("projects/" + projectId + "/secrets/wildfire_api_portal/versions/latest")
	wildfire_api_key := getSecretValue("projects/" + projectId + "/secrets/wildfire_api_key/versions/latest")

	url := "https://" + wildfire_api_portal + "/publicapi/submit/file"

	body := &bytes.Buffer{}

	file := strings.NewReader(contents)

	writer := multipart.NewWriter(body)
	part, _ := writer.CreateFormFile("file", filepath.Base(filename))
	_, err := io.Copy(part, file)
	if err != nil {
		log.Print(err)
	}

	err = writer.WriteField("apikey", wildfire_api_key)
	if err != nil {
		log.Print(err)
	}

	writer.Close()

	r, _ := http.NewRequest("POST", url, body)
	r.Header.Add("Content-Type", writer.FormDataContentType())

	client := &http.Client{}
	resp, err := client.Do(r)
	if err != nil {
		log.Print(err)
	}

	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	var uploadResponse wildfireUpload

	err = xml.Unmarshal(content, &uploadResponse)
	if err != nil {
		fmt.Println(err)
	}

	if uploadResponse.Error != "" {
		fmt.Printf("error: %v \n", uploadResponse.Error)
		return fmt.Errorf("%v", uploadResponse.Error)
	}

	return nil
}

func moveFile(srcBucket, dstBucket, objName string) error {
	ctx := context.Background()
	client, err := storage.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("storage.NewClient: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()

	src := client.Bucket(srcBucket).Object(objName)
	dst := client.Bucket(dstBucket).Object(objName)

	if _, err := dst.CopierFrom(src).Run(ctx); err != nil {
		return fmt.Errorf("Object(%q).CopierFrom(%q).Run: %v", objName, objName, err)
	}
	if err := src.Delete(ctx); err != nil {
		return fmt.Errorf("Object(%q).Delete: %v", objName, err)
	}
	fmt.Printf("Blob %v moved to %v.\n", objName, dstBucket)
	return nil
}

// gets the contents of the gcs bucket object and returns it a
func getFileContents(bucket, object string) string {
	ctx := context.Background()
	client, err := storage.NewClient(ctx)
	if err != nil {
		log.Fatal(err)
	}
	rc, err := client.Bucket(bucket).Object(object).NewReader(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer rc.Close()
	body, err := ioutil.ReadAll(rc)
	if err != nil {
		log.Fatal(err)
	}

	return string(body)
}

// CloudFunction Entrypoint
func GCSFileUploaded(ctx context.Context, e GCSEvent) error {

	quarantineBucket := os.Getenv("QUARANTINE_BUCKET")
	cleanBucket := os.Getenv("SCANNED_BUCKET")

	// Set md5Hash to the MD% Hash on the GCS Object
	md5Hash := decodeGCSMD5Value(e.MD5Hash)

	// Check if Wildfire has a verdict for the file by MD5 Hash
	verdict := checkWildfireVerdictByMD5(md5Hash)

	fmt.Printf("md5 hash: %v, verdict: %v \n", md5Hash, verdict)

	switch verdict {

	// if standard verdict, then update file metadata with result
	case "benign":
		err := moveFile(e.Bucket, cleanBucket, e.Name)
		if err != nil {
			log.Print(err)
		}

	case "malware", "phishing":
		err := moveFile(e.Bucket, quarantineBucket, e.Name)
		if err != nil {
			log.Print(err)
		}

		// if not a standard verdict, upload the file for analysis
	default:
		contents := getFileContents(e.Bucket, e.Name)
		fmt.Printf("uploading %v to wildfire for analysis \n", e.Name)
		err := uploadFileToWildfire(e.Name, contents)
		if err != nil {
			return err
		}

		for {
			time.Sleep(60 * time.Second)
			verdict := checkWildfireVerdictByMD5(md5Hash)

			switch verdict {
			case "malware", "phishing":
				fmt.Printf("md5 hash: %v, verdict: %v \n", md5Hash, verdict)
				err := moveFile(e.Bucket, quarantineBucket, e.Name)
				if err != nil {
					log.Print(err)
				}
                return nil

			case "benign":
				fmt.Printf("md5 hash: %v, verdict: %v \n", md5Hash, verdict)
				err := moveFile(e.Bucket, cleanBucket, e.Name)
				if err != nil {
					log.Print(err)
				}
				return nil

			default:
				fmt.Println("waiting for analysis...")
			}
		}
	}

	// return nothing
	return nil
}
