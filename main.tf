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

# ---------------------------------------------------------------------------------------------------------------------
#  Package cloud function source file into zip
# ---------------------------------------------------------------------------------------------------------------------

data "archive_file" "source" {
  type        = "zip"
  source_dir = "${path.module}/cloudfunction_code/"
  output_path = "${path.module}/tmp/cloudfunction_code.zip"
}

# ---------------------------------------------------------------------------------------------------------------------
#  Create a unique prefix for the naming of GCP resources
# ---------------------------------------------------------------------------------------------------------------------

# create a random pet name for the prefix of the resources
resource "random_pet" "unique_name" {
  prefix    = var.naming_prefix
  length    = 1
  separator = "-"
}

# ---------------------------------------------------------------------------------------------------------------------
#  Secret Manager secrets for use by the Cloud Function to Call Wildfire API
# ---------------------------------------------------------------------------------------------------------------------

# create secret for wildfire api key
resource "google_secret_manager_secret" "wildfire_api_key" {
  project   = var.gcp_project_id
  secret_id = "wildfire_api_key"
  replication {
    automatic = true
  }
}

# set the value for the secret
resource "google_secret_manager_secret_version" "wildfire_api_key" {
  secret      = google_secret_manager_secret.wildfire_api_key.id
  secret_data = var.wildfire_api_key
}

# give the cloud function access to the wildfire api key secret
resource "google_secret_manager_secret_iam_binding" "wildfire_api_key" {
  members   = ["serviceAccount:${google_service_account.cloudfunction.email}"]
  role      = "roles/secretmanager.secretAccessor"
  secret_id = google_secret_manager_secret.wildfire_api_key.id
}

# create secret for wildfire api portal
resource "google_secret_manager_secret" "wildfire_api_portal" {
  project   = var.gcp_project_id
  secret_id = "wildfire_api_portal"
  replication {
    automatic = true
  }
}

# set the value for the secret
resource "google_secret_manager_secret_version" "wildfire_api_portal" {
  secret      = google_secret_manager_secret.wildfire_api_portal.id
  secret_data = var.wildfire_api_portal
}

# give the cloud function access to the wildfire api portal secret
resource "google_secret_manager_secret_iam_binding" "wildfire_api_portal" {
  members   = ["serviceAccount:${google_service_account.cloudfunction.email}"]
  role      = "roles/secretmanager.secretAccessor"
  secret_id = google_secret_manager_secret.wildfire_api_portal.id
}

# ---------------------------------------------------------------------------------------------------------------------
#  Service Account for the Cloud Function to use to authenticate to Google Services
# ---------------------------------------------------------------------------------------------------------------------

# cloud function service account
resource "google_service_account" "cloudfunction" {
  project    = var.gcp_project_id
  account_id = "${random_pet.unique_name.id}-wildfire-scan"
}

# assign cloud function serice account project level storage admin
resource "google_project_iam_member" "cloudfunction_storage_admin" {
  project = var.gcp_project_id
  member  = "serviceAccount:${google_service_account.cloudfunction.email}"
  role    = "roles/storage.admin"
}

# create a GCS bucket for the initial upload of files
resource "google_storage_bucket" "upload" {
  #checkov:skip=CKV_GCP_62:No logging needed for demo environment
  project                     = var.gcp_project_id
  name                        = "${random_pet.unique_name.id}-upload"
  location                    = var.gcp_region
  uniform_bucket_level_access = true
  force_destroy = true
}

# create a GCS bucket for the files that have been scanned and found to be not benign
resource "google_storage_bucket" "quarantine" {
  #checkov:skip=CKV_GCP_62:No logging needed for demo environment
  project                     = var.gcp_project_id
  name                        = "${random_pet.unique_name.id}-quarantine"
  location                    = var.gcp_region
  uniform_bucket_level_access = true
  force_destroy = true
}

# create a GCS bucket for the files that have been scanned and found to be benign
resource "google_storage_bucket" "scanned" {
  #checkov:skip=CKV_GCP_62:No logging needed for demo environment
  project                     = var.gcp_project_id
  name                        = "${random_pet.unique_name.id}-scanned"
  location                    = var.gcp_region
  uniform_bucket_level_access = true
  force_destroy = true
}

# ---------------------------------------------------------------------------------------------------------------------
#  Cloud function for wildfire scanning of uploaded files
# ---------------------------------------------------------------------------------------------------------------------

resource "google_storage_bucket" "code" {
  #checkov:skip=CKV_GCP_62:No logging needed for demo environment
  project                     = var.gcp_project_id
  name = "${random_pet.unique_name.id}-code"
  location                    = var.gcp_region
  uniform_bucket_level_access = true
  force_destroy = true
}

resource "google_storage_bucket_object" "code" {
  bucket = google_storage_bucket.code.name
  name   = "cloudfunction_code.zip"
  source = data.archive_file.source.output_path
}


# cloud function deployment of scanned files
resource "google_cloudfunctions_function" "file_upload" {
  project = var.gcp_project_id
  name    = "${random_pet.unique_name.id}-wildfire-scan"
  runtime = "go116"
  region  = var.gcp_region

  ingress_settings = "ALLOW_INTERNAL_ONLY"

  event_trigger {
    event_type = "google.storage.object.finalize"
    resource   = google_storage_bucket.upload.name
  }

  entry_point = "GCSFileUploaded"
  timeout     = 540

  environment_variables = {
    QUARANTINE_BUCKET = google_storage_bucket.quarantine.name
    SCANNED_BUCKET    = google_storage_bucket.scanned.name
    GCP_PROJECT       = var.gcp_project_id
  }

  service_account_email = google_service_account.cloudfunction.email

  source_archive_bucket = google_storage_bucket.code.name
  source_archive_object = google_storage_bucket_object.code.name


}