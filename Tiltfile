docker_build('conceptmasters/sti-ct', '.', 
    dockerfile='Dockerfile.dev', ignore=['cmd/cert_tool', 'README.md'])
k8s_yaml('deployments/sti-ct-deployment.yaml')
k8s_resource('sti-ct', port_forwards=9009)