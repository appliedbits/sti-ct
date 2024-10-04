docker_build('conceptmasters/sti-ct', '.', 
    dockerfile='Dockerfile.dev')
k8s_yaml('deployments/sti-ct-deployment.yaml')
k8s_resource('sti-ct', port_forwards=9009)