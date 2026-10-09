// CI for ai-scanner-backend.
//
// What it does, in order:
//   1. Test     run every test suite in this repository
//   2. Build    build the two images, review-api and scanner-worker, into tar files
//   3. Scan     Trivy scans both images; a fixable CRITICAL vulnerability fails the build
//   4. Push     push both images to the registry (main branch only)
//   5. Deploy   commit the new tag to ai-scanner-backend-deployment (main only);
//               Argo CD sees the commit and rolls the cluster to it
//
// Where the images go is decided by two Jenkins global variables
// (Manage Jenkins > System > Global properties), so the same file serves both
// environments:
//   REGISTRY_KIND=local  REGISTRY=10.0.0.39:30500                              (K3S-SRV, plain HTTP)
//   REGISTRY_KIND=ecr    REGISTRY=<account>.dkr.ecr.<region>.amazonaws.com  AWS_REGION=<region>   (EKS)
// Credentials (Manage Jenkins > Credentials), never in this file:
//   github-deploy  username + fine-grained token that may push to the deployment repositories
//   aws-ecr        only for ECR from outside AWS: access key id + secret (on EKS use IRSA instead and leave AWS_CREDENTIALS_ID empty)

def IMAGES = [
    // name in the registry, BuildKit arguments that build it
    [name: 'review-api',
     args: '--local context=. --local dockerfile=. ' +
           '--opt context:mcp-server=local:mcp-server --local mcp-server=mcp-server ' +
           '--opt context:scanner=local:scanner --local scanner=scanner'],
    [name: 'scanner-worker',
     args: '--local context=scanner-worker --local dockerfile=scanner-worker ' +
           '--opt context:mcp-server=local:mcp-server --local mcp-server=mcp-server ' +
           '--opt context:scanner=local:scanner --local scanner=scanner'],
]

pipeline {
    agent {
        kubernetes {
            yamlFile 'ci/pod.yaml'          // the Pod with python, buildkit, trivy, aws and git
            defaultContainer 'python'
        }
    }
    options {
        disableConcurrentBuilds()            // two builds of main would race on the deployment repo
        timeout(time: 60, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '30'))
    }
    environment {
        REGISTRY_KIND = "${env.REGISTRY_KIND ?: 'local'}"
        REGISTRY      = "${env.REGISTRY ?: '10.0.0.39:30500'}"
        TAG           = "${env.GIT_COMMIT.take(7)}"        // the image tag is the commit it was built from
        DEPLOY_REPO   = 'DevOpsCourse22/ai-scanner-backend-deployment'
    }

    stages {
        stage('Test') {
            steps {
                container('python') {
                    sh '''
                        python -m pip install --quiet --upgrade pip
                        # scanner needs Semgrep only to run real scans; the tests fake it, so skip the big download
                        python -m pip install --quiet --no-deps -e ./scanner
                        python -m pip install --quiet -e "./mcp-server[dev]" -e ".[dev,kubernetes]"
                        mkdir -p test-results
                        (cd mcp-server     && python -m pytest -q --junitxml=../test-results/mcp-server.xml)
                        python -m pytest -q tests          --junitxml=test-results/review-api.xml
                        (cd scanner        && python -m pytest -q --junitxml=../test-results/scanner.xml)
                        (cd scanner-worker && python -m pytest -q --junitxml=../test-results/scanner-worker.xml)
                        python -m pytest -q security-tests --junitxml=test-results/security-tests.xml
                    '''
                }
            }
            post { always { junit 'test-results/*.xml' } }
        }

        stage('Build') {
            steps {
                container('buildkit') {
                    script {
                        for (img in IMAGES) {
                            sh """
                                buildctl-daemonless.sh build --frontend dockerfile.v0 ${img.args} \
                                  --output type=docker,name=${REGISTRY}/${img.name}:${TAG},dest=${img.name}.tar
                            """
                        }
                    }
                }
            }
        }

        stage('Scan') {
            steps {
                container('trivy') {
                    script {
                        for (img in IMAGES) {
                            // the full HIGH+CRITICAL report is kept with the build ...
                            sh "trivy image --quiet --input ${img.name}.tar --severity HIGH,CRITICAL --ignore-unfixed --format table --output trivy-${img.name}.txt"
                            // ... and only a CRITICAL vulnerability that has a fix stops the pipeline
                            sh "trivy image --quiet --input ${img.name}.tar --severity CRITICAL --ignore-unfixed --exit-code 1"
                        }
                    }
                }
            }
            post { always { archiveArtifacts artifacts: 'trivy-*.txt', allowEmptyArchive: true } }
        }

        stage('Push') {
            when { branch 'main' }
            steps {
                script {
                    if (env.REGISTRY_KIND == 'ecr') { ecrLogin() }
                    def insecure = env.REGISTRY_KIND == 'local' ? ',registry.insecure=true' : ''
                    container('buildkit') {
                        for (img in IMAGES) {
                            // same inputs as the Build stage, so BuildKit reuses its cached layers: this only uploads
                            sh """
                                buildctl-daemonless.sh build --frontend dockerfile.v0 ${img.args} \
                                  --output type=image,name=${REGISTRY}/${img.name}:${TAG},push=true${insecure}
                            """
                        }
                    }
                }
            }
        }

        stage('Deploy') {
            when {
                allOf { branch 'main'; expression { env.UPDATE_DEPLOY_REPO != 'false' } }
            }
            steps {
                container('git') {
                    withCredentials([usernamePassword(credentialsId: 'github-deploy',
                                                      usernameVariable: 'GIT_USER', passwordVariable: 'GIT_PASS')]) {
                        sh '''
                            set -eu
                            . ci/deploy-lib.sh
                            clone_deploy_repo
                            set_image review-api kustomization.yaml
                            # review-api starts each review as a Job running this image; the name is an env var, which Kustomize does not rewrite
                            sed -i "s|value: [^ ]*scanner-worker:[^ ]*|value: ${REGISTRY}/scanner-worker:${TAG}|" review-api/deployment.yaml
                            commit_and_push "review-api and scanner-worker"
                        '''
                    }
                }
            }
        }
    }

    post {
        always { sh 'rm -f *.tar .ecr-password' }   // never keep image tars or a login token in the workspace
    }
}

// ECR has no fixed password: ask AWS for a 12-hour token and write it where BuildKit looks for logins.
def ecrLogin() {
    def body = {
        container('aws') {
            sh 'aws ecr get-login-password --region "$AWS_REGION" > .ecr-password'
        }
        container('buildkit') {
            sh '''
                mkdir -p "$HOME/.docker"
                AUTH=$(printf 'AWS:%s' "$(cat .ecr-password)" | base64 | tr -d '\\n')
                printf '{"auths":{"%s":{"auth":"%s"}}}' "$REGISTRY" "$AUTH" > "$HOME/.docker/config.json"
                rm -f .ecr-password
            '''
        }
    }
    if (env.AWS_CREDENTIALS_ID) {
        withCredentials([usernamePassword(credentialsId: env.AWS_CREDENTIALS_ID,
                                          usernameVariable: 'AWS_ACCESS_KEY_ID', passwordVariable: 'AWS_SECRET_ACCESS_KEY')]) {
            body()
        }
    } else {
        body()   // on EKS: the Pod's service account gives AWS access (IRSA), no keys needed
    }
}
