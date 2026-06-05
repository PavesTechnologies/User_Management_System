pipeline {
    agent { label 'worker' }

    environment {
        IMAGE_NAME = "ums-service"
        CONTAINER_NAME = "ums-container"
    }

    stages {

        stage('Checkout Code') {
            steps {
                echo "Cloning repository..."
                checkout scm
            }
        }

        stage('Python Setup/Installation') {
            steps {
                echo "Setting up Python..."
                sh '''
                if ! command -v python3 &> /dev/null
                then
                    echo "Python3 not found. Installing..."
                    sudo apt-get update
                    sudo apt-get install -y python3 python3-venv python3-pip
                else
                    echo "Python3 already installed"
                fi

                python3 --version
                pip3 --version
                '''
            }
        }

        stage('Install Dependencies') {
            steps {
                echo "Installing Python dependencies..."
                sh '''
                python3 -m venv ums-venv
                . ums-venv/bin/activate
                pip install --upgrade pip
                pip install -r Backend/requirements.txt
                '''
            }
        }

        stage('loading environment variables') {
            steps {
                echo "Loading environment variables..."
                sh """
                aws secretsmanager get-secret-value \
                    --secret-id dev-ums \
                    --region ap-south-1 \
                    --query SecretString \
                    --output text | jq -r 'to_entries|map("\\(.key)=\\(.value)")|.[]' > Backend/.env
                """
            
                echo "Converted AWS secret JSON → .env file"
            }
        }

        stage('Code Quality Check and tests') {
            steps {
                echo "Running code quality checks and tests..."
                sh '''
                . ums-venv/bin/activate
                chmod +x scripts/quality_check.sh
                ./scripts/quality_check.sh
                '''
            }
        }

    }

    post {
        success {
            echo "Pipeline completed successfully"
        }
        failure {
            echo "Pipeline failed"
        }
    }
}
