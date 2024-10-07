# STI-CT

TBD

## Installation

This section explains how to set up the STI-CT service on your local Kubernetes cluster.

### Step 1: Set Up the Environment

First, ensure you have Docker and Kubernetes set up on your machine. Also, ensure you have Go installed. 

### Step 2: Clone the Google Trillian Repository

Clone the Google Trillian repository to get the source code.

```sh
git clone https://github.com/google/trillian.git
cd trillian
```

### Step 3: Build Docker Images

Build the Docker images for the Trillian Log Server and Trillian Log Signer.

```sh
docker build -t trillian-log-server -f examples/deployment/docker/log_server/Dockerfile .
docker build -t trillian-log-signer -f examples/deployment/docker/log_signer/Dockerfile .
```

### Step 4: Push Docker Images to a Registry

If you're using Docker for Mac, you can use the local Docker registry. However, if you are using a remote Kubernetes cluster, you need to push these images to a Docker registry. For simplicity, we'll assume you have access to Docker Hub.

Replace `your-dockerhub-username` with your actual Docker Hub username.

```sh
docker tag trillian-log-server your-dockerhub-username/trillian-log-server:latest
docker tag trillian-log-signer your-dockerhub-username/trillian-log-signer:latest

docker push your-dockerhub-username/trillian-log-server:latest
docker push your-dockerhub-username/trillian-log-signer:latest
```

### Step 5: Deploy MySQL

Apply the deployment file for MySQL:

```sh
kubectl apply -f deployments/mysql-deployment.yaml
```

### Step 6: Deploy Trillian Log Server and Trillian Log Signer

Apply the deployment files for the Trillian Log Server and Trillian Log Signer:

```sh
kubectl apply -f deployments/trillian-deployment.yaml
```

### Step 7: Deploy the STI-CT Service

First, create a secret containing the PEM file with both public and private keys.

1. Create a PEM file (e.g., signer-keys.pem) containing your keys.
2. Create a Kubernetes Secret from this file:

```sh
kubectl create secret generic signer-keys --from-file=signer-keys.pem=path/to/your/signer-keys.pem -n stict
```

Next, create a secret containing trusted root certificates.

```sh
kubectl create secret generic trusted-roots \
  --from-file=root1.pem=path/to/root1.pem \
  --from-file=root2.pem=path/to/root2.pem \
  --from-file=root3.pem=path/to/root3.pem \
  -n stict
```

If you need to replace the existing secret, you can first delete existing ones and then create new ones.

```sh
kubectl delete secret trusted-roots -n stict
```

Apply the deployment:

```sh
kubectl apply -f deployments/sti-ct-deployment.yaml
```

### Step 8: Verify the Deployments

Check the status of the pods to ensure everything is running correctly:

```sh
kubectl get pods
```

Check the services to ensure they are exposed correctly:

```sh
kubectl get services
```

### Step 9: Initialize the Trillian Log

Run the initialization commands to create the necessary Trillian logs:

1. Port-forward the MySQL service to your local machine:

```sh
kubectl port-forward svc/mysql 3306:3306
```

2. Initialize the Trillian MySQL schema:

```sh
MYSQL_ROOT_PASSWORD=password MYSQL_DATABASE=trillian MYSQL_USER=trillian MYSQL_PASSWORD=trillian MYSQL_HOST=127.0.0.1 MYSQL_USER_HOST=127.0.0.1  ./scripts/resetdb.sh
```

### Step 10: Create Certificates

Build the `cert_tool` binary:

```sh
cd cmd/cert_tool
go build -o cert_tool main.go
```

Create sample certificate chain using cert_tool:

```sh
./cert_tool -type=root -cn="Root CA" -prefix=root -b64=yes
```

Notice, -b64=yes flag will output the certificate in base64 format.  This will be used to submit the pre certificate to the CT log.

Create an intermediate certificate:

```sh
./cert_tool -type=intermediate -cn="SCA" -prefix=intermediate -b64=yes
```

Create a delegate pre-certificate:

```sh
./cert_tool -type=delegate -cn="ACME Inc" -prefix=delegate -b64=yes
```

### Step 11: Submit Delegate Pre-Certificate to CT Log


```json
curl  -X POST \
  'http://localhost:9009/ct/v1/add-pre-chain' \
  --header 'Accept: */*' \
  --header 'Content-Type: application/json' \
  --data-raw '{
  "chain": [
    "<delegate cert>",
    "<internmediate cert>"
  ]
}'
```
